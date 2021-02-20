# python3
# Copyright 2019 The gVisor Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Machine abstraction passed to benchmarks to run docker containers.

Abstraction for interacting with test machines. Machines are produced
by Machine producers and represent a local or remote machine. Benchmark
methods in /benchmarks/suite are passed the required number of machines in order
to run the benchmark. Machines contain methods to run commands via bash,
possibly over ssh. Machines also hold a connection to the docker UNIX socket
to run contianers.

  Typical usage example:

  machine = Machine()
  machine.run(cmd)
  machine.pull(path)
  container = machine.container()
"""

import logging
import os
import re
import subprocess
import time
from typing import List, Tuple

import docker

from benchmarks import harness
from benchmarks.harness import container
from benchmarks.harness import machine_mocks
from benchmarks.harness import ssh_connection
from benchmarks.harness import tunnel_dispatcher

log = logging.getLogger(__name__)


class Machine(object):
  """The machine object is the primary object for benchmarks.

  Machine objects are passed to each metric function call and benchmarks use
  machines to access real connections to those machines.

  Attributes:
    _name: Name as a string
  """
  _name = ""

  def run(self, cmd: str) -> Tuple[str, str]:
    """Convenience method for running a bash command on a machine object.

    Some machines may point to the local machine, and thus, do not have ssh
    connections. Run runs a command either local or over ssh and returns the
    output stdout and stderr as strings.

    Args:
      cmd: The command to run as a string.

    Returns:
      The command output.
    """
    raise NotImplementedError

  def read(self, path: str) -> str:
    """Reads the contents of some file.

    This will be mocked.

    Args:
      path: The path to the file to be read.

    Returns:
      The file contents.
    """
    raise NotImplementedError

  def pull(self, workload: str) -> str:
    """Send the given workload to the machine, build and tag it.

    All images must be defined by the workloads directory.

    Args:
      workload: The workload name.

    Returns:
      The workload tag.
    """
    raise NotImplementedError

  def container(self, image: str, **kwargs) -> container.Container:
    """Returns a container object.

    Args:
      image: The pulled image tag.
      **kwargs: Additional container options.

    Returns:
        :return: a container.Container object.
    """
    raise NotImplementedError

  def sleep(self, amount: float):
    """Sleeps the given amount of time."""
    time.sleep(amount)

  def __str__(self):
    return self._name


class MockMachine(Machine):
  """A mocked machine."""
  _name = "mock"

  def run(self, cmd: str) -> Tuple[str, str]:
    return "", ""

  def read(self, path: str) -> str:
    return machine_mocks.Readfile(path)

  def pull(self, workload: str) -> str:
    return workload  # Workload is the tag.

  def container(self, image: str, **kwargs) -> container.Container:
    return container.MockContainer(image)

  def sleep(self, amount: float):
    pass


def get_address(machine: Machine) -> str:
  """Return a machine's default address."""
  default_route, _ = machine.run("ip route get 8.8.8.8")
  return re.search(" src ([0-9.]+) ", default_route).group(1)


class LocalMachine(Machine):
  """The local machine.

  Attributes:
    _name: Name as a string
    _docker_client: a pythonic connection to to the local dockerd unix socket.
      See: https://github.com/docker/docker-py
  """

  def __init__(self, name):
    self._name = name
    self._docker_client = docker.from_env()

  def run(self, cmd: str) -> Tuple[str, str]:
    process = subprocess.Popen(
        cmd.split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    return stdout.decode("utf-8"), stderr.decode("utf-8")

  def read(self, path: str) -> bytes:
    # Read the exact path locally.
    return open(path, "r").read()

  def pull(self, workload: str) -> str:
    # Run the docker build command locally.
    logging.info("Building %s@%s locally...", workload, self._name)
    with open(harness.LOCAL_WORKLOADS_PATH.format(workload),
              "rb") as dockerfile:
      self._docker_client.images.build(
          fileobj=dockerfile, tag=workload, custom_context=True)
    return workload  # Workload is the tag.

  def container(self, image: str, **kwargs) -> container.Container:
    # Return a local docker container directly.
    return container.DockerContainer(self._docker_client, get_address(self),
                                     image, **kwargs)

  def sleep(self, amount: float):
    time.sleep(amount)


class RemoteMachine(Machine):
  """Remote machine accessible via an SSH connection.

  Attributes:
    _name: Name as a string
    _ssh_connection: a paramiko backed ssh connection which can be used to run
      commands on this machine
    _tunnel: a python wrapper around a port forwarded ssh connection between a
      local unix socket and the remote machine's dockerd unix socket.
    _docker_client: a pythonic wrapper backed by the _tunnel. Allows sending
      docker commands: see https://github.com/docker/docker-py
  """

  def __init__(self, name, **kwargs):
    self._name = name
    self._ssh_connection = ssh_connection.SSHConnection(name, **kwargs)
    self._tunnel = tunnel_dispatcher.Tunnel(name, **kwargs)
    self._tunnel.connect()
    self._docker_client = self._tunnel.get_docker_client()
    self._has_installers = False

  def run(self, cmd: str) -> Tuple[str, str]:
    return self._ssh_connection.run(cmd)

  def read(self, path: str) -> str:
    # Just cat remotely.
    stdout, stderr = self._ssh_connection.run("cat '{}'".format(path))
    return stdout + stderr

  def install(self,
              installer: str,
              results: List[bool] = None,
              index: int = -1):
    """Method unique to RemoteMachine to handle installation of installers.

    Handles installers, which install things that may change between runs (e.g.
    runsc). Usually called from gcloud_producer, which expects this method to
    to store results.

    Args:
      installer: the installer target to run.
      results: Passed by the caller of where to store success.
      index: Index for this method to store the result in the passed results
        list.
    """
    # This generates a tarball of the full installer root (which will generate
    # be the full bazel root directory) and sends it over.
    if not self._has_installers:
      archive = self._ssh_connection.send_installers()
      self.run("tar -xvf {archive} -C {dir}".format(
          archive=archive, dir=harness.REMOTE_INSTALLERS_PATH))
      self._has_installers = True

    # Execute the remote installer.
    self.run("sudo {dir}/{file}".format(
        dir=harness.REMOTE_INSTALLERS_PATH, file=installer))

    if results:
      results[index] = True

  def pull(self, workload: str) -> str:
    # Push to the remote machine and build.
    logging.info("Building %s@%s remotely...", workload, self._name)
    remote_path = self._ssh_connection.send_workload(workload)
    remote_dir = os.path.dirname(remote_path)
    # Workloads are all tarballs.
    self.run("tar -xvf {remote_path} -C {remote_dir}".format(
        remote_path=remote_path, remote_dir=remote_dir))
    self.run("docker build --tag={} {}".format(workload, remote_dir))
    return workload  # Workload is the tag.

  def container(self, image: str, **kwargs) -> container.Container:
    # Return a remote docker container.
    return container.DockerContainer(self._docker_client, get_address(self),
                                     image, **kwargs)

  def sleep(self, amount: float):
    time.sleep(amount)
