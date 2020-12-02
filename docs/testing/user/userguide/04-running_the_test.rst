.. This work is licensed under a Creative Commons Attribution 4.0 International
.. License.
.. http://creativecommons.org/licenses/by/4.0
.. (c) OPNFV, Intel Corporation and others.

================
Running the test
================
.. _NFV-TST009: https://docbox.etsi.org/ISG/NFV/open/Publications_pdf/Specs-Reports/NFV-TST%20009v3.2.1%20-%20GS%20-%20NFVI_Benchmarks.pdf
.. _TST009_Throughput_64B_64F.test: https://github.com/opnfv/samplevnf/blob/master/VNFs/DPPD-PROX/helper-scripts/rapid/TST009_Throughput_64B_64F.test
.. _rapid_location: https://github.com/opnfv/samplevnf/blob/master/VNFs/DPPD-PROX/helper-scripts/rapid/

Overview
--------
A default test will be run automatically when you launch the testing. The
details and definition of that test is defined in file
TST009_Throughput_64B_64F.test_.

We will discuss the sections of such a test file and how this can be changed to
accomodate the testing you want to execute. This will be done by creating your
own test file and making sure it becomes part of your testcases.yaml, as will
be shown below.

Test File Description
---------------------
The test file has multiple sections. The first section is a generic section
called TestParameters. Then there are 1 or more sections desribing the test
machines we will be using in the test. The sections are named TestMx, where x
is a number (starting with 1). The tests to be executed are described in a
section called testy, where y is the number of the test to be executed,
starting with 1. In this automated testing driven by Xtesting, we will
typically only run 1 test.

TestParameters
^^^^^^^^^^^^^^
In this section, the name of the test is specified. This is only used in the
reporting and has no influence on the actual testing.

.. code-block:: console

     name = Rapid_ETSINFV_TST009

The number of test that will be executed by this run and that will be described
in the [testy] sections, is defined by the number_of_tests parameter. In the
Xtesting framework that we are using here, this will typically be set to 1.

.. code-block:: console

     number_of_tests = 1

The total number of machines to be used in this testing will be defined by the
parameter total_number_of_test_machines. The function that these machines have
in this test will be described in the [TestMx] section. Typically, this number
will be set to 2, but many more machines can particiapte in a test.

.. code-block:: console

     total_number_of_test_machines = 2

lat_percentile is a variable that is setting which percentile to use during the
course of this test. This will be used to report the percentile round trip
latency and is a better measurement for the high latencies during this test than
the maximum latency which will also be reported. Note that we also report the
total round trip latency histogram.

.. code-block:: console

     lat_percentile = 99


TestMx
^^^^^^
In the TestMx sections, where x denotes the index of the machine, the function
of the machine in the testing, will be described. The machine can be defined as
a generator, or as a packet reflector (swap function). The machines can be any
machine that is created upfront (See step 3 of the installation steps). Other
functions can also be executed by the test machines and examples of test files
can be found in rapid_location_.

The first parameter is the name of the machine and is only used for referencing
the machine. This will be the name of the PROX instance and will be shown in
case you run the PROX UI. In this automated testing, this will be not be
visible.

The PROX config file is used by the PROX program and defines what PROX will be
doing. For a generator, this will typically be gen.cfg. Multiple cfg files
exist in the rapid_location_. dest_vm is used by a generator to find out to
which VM he needs to send the packets. Int e example below, the packets will be
sent to TestM2. gencores is a list of cores to be used for the generator tasks.
Note that if you specify more than 1 core, the interface will need to support as
many tx queues as there are generator cores. The latcores field specifies a
list of cores to be used by the latency measurement tasks. You need as many rx
queueus on the interface as the number of latcores. The default value for the
bucket_size_exp parameter is 12. It is also its minimum value. In case most of
the latency measurements in the histogram are falling in the last bucket, this
number needs to be increased. Every time you increase this number by 1, the
bucket size for the latency histogram is multiplied by 2. There are 128 buckets
in the histogram.
cores is a parameter that will be used by non-generator configurations that
don't need a disctinction between generator and latency cores (e.g. swap.cfg).

Changing these parameters requires in depth knowledge of the PROX tool and is
not something to start with.

.. code-block:: console

     name = Generator
     config_file = gen.cfg
     dest_vm = 2
     gencores = [1]
     latcores = [3]
     #bucket_size_exp = 12
testy
^^^^^
In the testy sections, where y denotes the index of the test, the test that will
be executed on the machines that were specified in the TestMx sections, will be
described. Using Xtesting, we will typically only use 1 test.
Parameter test is defining which test needs to be run. This is a hardcoded
string and can only be one of the following ['flowsizetest', 'TST009test',
'fixed_rate', 'increment_till_fail', 'corestats', 'portstats', 'impairtest',
'irqtest', 'warmuptest']. In this project, we will use the TST009test testing.
For examples of the other tests, please check out the other test files in
rapid_location_.

The pass_threshold parameter defines the success criterium for the test. When
this test uses multiple combinations of packet size and flows, all combinations
must be meeting the same threshold. The threshold is expressed in Mpps.

The imixs parameter defines the pakcet sizes that will be used. Each element in
the imix list will result in a separate test. Each element is on its turn a
list of packet sizes which will be used during one test execution. If you only
want to test 1 imix size, define imixs with only one element. For each element in
the imixs list, the generator will iterate over the packet lengths and send them
out in the order as specified in the list. An example of an imix list is [128,
256, 64, 64, 128]. In this case, 40% of the packets will have a size of 64
bytes, 40% will have a packet size of 128 and 20% will have a packet size of
256. When using this with Xtesting, we will typically only use 1 imix. When
needing results for more sizes, one should create a specific test file per size
and launch the different tests using Xtesting.

The flows parameter is a list of flow sizes. For each flow size, a test will be
run with the specified amount of flows. The flow size needs to be powers of 2,
max 2^30. If not a power of 2, we will use the lowest power of 2 that is larger
than the requested number of flows. e.g. 9 will result in 16 flows.
Same remark as for the imixs parameter: we will only use one element in the
flows list. When more flows need to be tested, create a differnt test file and
launch it using Xtesting.

drop_rate_threshold specifies the ratio of packets than can be dropped and still
consider the test run as succesful. Note that a value of 0 means a zero packet
loss: even if we lose 1 packet during a certain step in a test run, it will be
marked as failed.

lat_avg_threshold, lat_perc_threshold, lat_max_threshold are threshols to define
the maximal acceptable round trip latency to mark the test step as successful.
You can set this threshold for the average, the percentile and the maximum
latency. Which percentile is being used is define in the TestParameters section.
All these thresholds are expressed in micro-seconds. You can also put the value
to inf, which means the threshold will never be reached and hence the threshold
value is not being used to define if the run is successful or not.

MAXr, MAXz, MAXFramesPerSecondAllIngress and StepSize are defined in
NFV-TST009_ and are used to control the binary search algorithm.

ramp_step is a variable that controls the ramping of the generated traffic. When
not specified, the requested traffic for each step in the testing will be
applied immediately. If specified, the generator will slowly go to the requested
speed by increasing the traffic each second with the value specified in this
parameter till it reached the requested speed. This parameter is expressed in
100Mb/s.

.. code-block:: console

     pass_threshold=0.001
     imixs=[[64]]
     flows=[64]
     drop_rate_threshold = 0
     lat_avg_threshold = inf
     lat_perc_threshold = inf
     lat_max_threshold = inf
     MAXr = 3
     MAXz = 5000
     MAXFramesPerSecondAllIngress = 12000000
     StepSize = 10000
     #ramp_step = 1

Modifying the test
------------------
In case you want to modify the parameters as specified in
TST009_Throughput_64B_64F.test_, it is best to create your own test file. Your
test file will need to be uploaded to the test container. Hence you will have to
rebuild your container, and add an extra copy command to the Dockerfile so that
your new test file will be avaialble in the container.
Then you will need to modify the testcases.yaml file. One of the args that you
can specify is the test_file. Put your newly created test file as the new value
for this argument.
Now build and publish your test container as specified in steps 5 & 6 of the
installation procedure.

Note that other arguments than test_file can be specified in testcases.yaml. For
a list of arugments, please check out the test_params dictionary in the
rapid_defaults.py that you can find in rapid_location_.
It is adviced not to change these parameters unless you have an in-depth
knowledge of the code.
The only 2 arguments that van be changed are the test_file which was already
discussed and the runtime argument. This argument defines how long each test run
will take and is expressed in seconds.
