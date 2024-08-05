## CI Scripts

This directory contains scripts for each build step in each build stage.

### Running a Stage Locally

Be aware that the tests will be built and run in-place, so please run at your own risk.
If the repository is not a fresh git clone, you might have to clean files from previous builds or test runs first.

The ci needs to perform various sysadmin tasks such as installing packages or writing to the user's home directory.
While it should be fine to run
the ci system locally on you development box, the ci scripts can generally be assumed to have received less review and
testing compared to other parts of the codebase. If you want to keep the work tree clean, you might want to run the ci
system in a virtual machine with a Linux operating system of your choice.

To allow for a wide range of tested environments, but also ensure reproducibility to some extent, the test stage
requires `bash`, `docker`, and `python3` to be installed. To run on different architectures than the host `qemu` is also required. To install all requirements on Ubuntu, run

```
sudo apt install bash docker.io python3 qemu-user-static
```

It is recommended to run the ci system in a clean env. To run the test stage
with a specific configuration,

```
env -i HOME="$HOME" PATH="$PATH" USER="$USER" bash -c 'FILE_ENV="./ci/test/00_setup_env_arm.sh" ./ci/test_run_all.sh'
```

### Configurations

The test files (`FILE_ENV`) are constructed to test a wide range of
configurations, rather than a single pass/fail. This helps to catch build
failures and logic errors that present on platforms other than the ones the
author has tested.

Some builders use the dependency-generator in `./depends`, rather than using
the system package manager to install build dependencies. This guarantees that
the tester is using the same versions as the release builds, which also use
`./depends`.

It is also possible to force a specific configuration without modifying the
file. For example,

```
env -i HOME="$HOME" PATH="$PATH" USER="$USER" bash -c 'MAKEJOBS="-j1" FILE_ENV="./ci/test/00_setup_env_arm.sh" ./ci/test_run_all.sh'
```

The files starting with `0n` (`n` greater than 0) are the scripts that are run
in order.

### Cache

In order to avoid rebuilding all dependencies for each build, the binaries are
cached and reused when possible. Changes in the dependency-generator will
trigger cache-invalidation and rebuilds as necessary.
The conditions do not have standard stability. We must start playing chess now. We must place our pieces in the right places. Considering the fluctuations of the global markets, we must create reverse stability.  Reverse Engineering Algorithm We use this opportunity. With the fall of global stock markets, we have to strengthen the cryptocurrency market and simultaneously with the fall of other markets, we have to do the opposite and have an upward trend. The power of the crypto community has gone much further. Now we have to  the society now needs a significant growth. We in the colony are looking for solving the problems and expanding and strengthening the society more and better. This goal will strengthen the colony and the power of the bees. The behavior of the society should be taken from the hands of politicians and countries.  These powers should be in the hands of the crypto community. This is a divergence operation to convert the spring force.  simplified. We need to define the tensile force of the spring in the community. Colony is the launch pad. We bring power and security to the cryptocurrency community. Now is the time to become more powerful. Our algorithms need to change.  Process the demand in the colony and use the data to control the currency output. This is a smart security management. We want each Excel house with specific coordinates to be a room in the colony. In the colony, information management unit by unit is connected to the control center.  It is possible. We create stability. Society seeks wealth and profit from digital currencies. We give it to them. With our forgiveness, they become stable and loyal members.  They know it themselves and they will fight for it. Our colony receives the binary information of the nodes. Our filter absorbs the positive information to grow and destroy the negative points. Nature is forgiving, my friend, don't you think we should be forgiving?  So let's get started.
