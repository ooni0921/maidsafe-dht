  * [Introduction](#Introduction.md)
  * [Dashboard](#Dashboard.md)
  * [Types of Tests](#Types_of_Tests.md)
  * [CMake Options](#CMake_Options.md)
  * [Building the Tests](#Building_the_Tests.md)
  * [Running the Tests](#Running_the_Tests.md)
    * [Running Google Test Executables Directly](#Running_Google_Test_Executables_Directly.md)
    * [Running Via CTest](#Running_Via_CTest.md)
    * [Sending Results to the Dashboard](#Sending_Results_to_the_Dashboard.md)

# Introduction #

maidsafe-dht uses [Google Test](http://code.google.com/p/googletest/downloads/list) to provide a suite of tests that should allow the validation of changes to the code. We configure and run the suite using [CTest](http://www.cmake.org/Wiki/CMake_Testing_With_CTest). We by no means claim that the code is 100% tested, and that is one of our big [TODOs](http://code.google.com/p/maidsafe-dht/wiki/TODO) right now. So, whether you think you'd like to contribute to the coverage of the project, or add extra functionality, the following comments will be useful when dealing with our tests.

# Dashboard #

We provide a [dashboard website](http://dash.maidsafe.net/index.php?project=maidsafe-dht), where the results of tests can be uploaded and monitored. Every developer runs an Experimental (`make Experimental`) before committing code. Once the code is committed several other machines with different platforms run the tests and post their results. This way developers can see if any changes made, although valid on some platforms, have negatively affected any others. To add a machine to the set of machines already on the [dashboard](http://dash.maidsafe.net/index.php?project=maidsafe-dht), simply run periodically a script that updates the local svn repository and then runs all tests. The results will be posted after that. If you give a descriptive name to your machine it will help a lot.

# Types of Tests #

We distinguish between two different types of tests in this project. We do not do unit tests _per se_, but either Behavioural or Functional ones. **Behaviourals** usually are used to test the possible behaviours of several functions of a particular component, and we try to keep them fairly short, **under ten seconds** on average. **Functionals**, on the other hand, usually test the interaction between several components, and thus take **longer than ten seconds**.

**N.B.** When running tests via CTest, behavioural tests timeout after **sixty seconds** and functional ones after **ten minutes**. Any such timeouts when running an Experimental or Continuous build will be reported as failures to the dashboard.  To categorise a test as functional or behavioural, simply name it with a leading `BEH_` or `FUNC_`, make the appropriate target (e.g. `make TESTbase`) and run CMake again.  Tests not named this way will generate a CMake developer warning.

There is no timeout when running the tests directly via the gtest executable (see [Running the Tests](#Running_the_Tests.md) below for more detailed instructions).

# CMake Options #

For full details on creating the build environment using CMake, see [Developer Build Instructions](http://code.google.com/p/maidsafe-dht/wiki/DevBuild).

When running CMake there is a settable option which causes CTest to run only Behavioural tests, only Functional tests or both types. To set the test type, run:
  * `cmake ../.. -DMAIDSAFE_TEST_TYPE=BEH` - Behavioural<br>
<ul><li><code>cmake ../.. -DMAIDSAFE_TEST_TYPE=FUNC</code> - Functional<br>
</li><li><code>cmake ../.. -DMAIDSAFE_TEST_TYPE=_</code> - All (underscore)</li></ul>

<h1>Building the Tests</h1>

Our test executables are <a href='http://code.google.com/p/googletest/downloads/list'>Google Tests</a> which can be run directly or via CTest.  The executables are made by running <code>make $target</code> in the maidsafe-dht build directory where <code>$target</code> is one of the available test groups, or via your chosen IDE.  These groups' names generally reflect the directory structure of the source code, so e.g. tests covering the code in <code>src/maidsafe/base</code> are part of the target <code>TESTbase</code>.  The available test targets are:<br>
<ul><li><code>TESTbase</code>
</li><li><code>TESTboost</code>
</li><li><code>TESTkademlia</code>
</li><li><code>TESTknode</code> (this is a long functional test suite which sets up a small, local Kademlia network)<br>
</li><li><code>TESTnatpmp</code>
</li><li><code>TESTrpcprotocol</code>
</li><li><code>TESTtransport</code>
</li><li><code>TESTupnp</code>
</li><li><code>cryptest</code> (the test suite provided as part of <a href='http://www.cryptopp.com'>Crypto++</a>)<br>
If you add a new test, re-running CMake warns you if the new test's name conflicts with an existing one (names of individual tests should be unique).<br><br></li></ul>

<h1>Running the Tests</h1>

As mentioned above, the test executables can be run directly or via CTest.<br>
<br>
<h3>Running Google Test Executables Directly</h3>

For a complete guide to Google Test options please refer to <a href='http://code.google.com/p/googletest/w/list'>http://code.google.com/p/googletest/w/list</a>. However we offer these pointers:<br>
<ul><li>Filtering groups of tests is possible. Each test executable has a distinctive name which allows execution of just the tests in that file. So, e.g. to run all the tests in <code>TESTbase</code>, simply run:<br>
<ul><li><code>build/Linux/Debug/bin/TESTbase</code> (assuming it was build in Debug mode for Linux - see <a href='#CMake_Options.md'>CMake Options</a> above for more info).</li></ul></li></ul>

<ul><li>To filter even further, an individual test name can be used to single it out. Meta-characters such as the <code>*</code> symbol can be used in the filter, e.g.:<br>
<ul><li><code>build/Linux/Debug/bin/TESTbase --gtest_filter=*BEH_BASE_RandomString</code>
</li><li><code>build/Linux/Debug/bin/TESTbase --gtest_filter=*RandomStri*</code>
</li><li><code>build/Linux/Debug/bin/TESTbase --gtest_filter=*BEH_*</code> (runs all behavioural tests in <code>TESTbase</code>)</li></ul></li></ul>

<ul><li>Repetition and breaking of execution can also be specified when running any of the tests. For repetition, use <code>-1</code> to indicate infinite cycles. Using the <code>gtest_break_on_failure</code> flag might be particularly useful with the <code>-1</code>, e.g.:<br>
<ul><li><code>build/Linux/Debug/bin/TESTbase --gtest_filter=*BEH_BASE_RandomString --gtest_repeat=10</code>
</li><li><code>build/Linux/Debug/bin/TESTbase --gtest_filter=*BEH_BASE_RandomString --gtest_repeat=-1 --gtest_break_on_failure</code></li></ul></li></ul>

<h3>Running Via CTest</h3>

For a complete guide to CTest options please refer to <a href='http://www.itk.org/Wiki/CMake_Testing_With_CTest#Running_Individual_Tests'>http://www.itk.org/Wiki/CMake_Testing_With_CTest#Running_Individual_Tests</a>. However we offer these pointers:<br>
<br>
<ul><li>To run all the tests via CTest, simply call <code>ctest</code> from the maidsafe-dht build directory.  If very few or no tests are run, you probably need to re-run <code>cmake ../..</code> to allow CTest to add the individual tests to its inventory.  CTest will list or run only the test types specified by the CMake variable MAIDSAFE_TEST_TYPE, i.e. Behavioural (default), Functional, or all tests.  See <a href='#CMake_Options.md'>CMake Options</a> above for further details.</li></ul>

<ul><li>To simply list all the tests and their index numbers without executing them, run:<br>
<ul><li><code>ctest -N</code></li></ul></li></ul>

<ul><li>To execute an individual test or a sequence of tests (e.g. just test no. 99, or tests no. 23 to 26), run:<br>
<ul><li><code>ctest -I 99,99</code>
</li><li><code>ctest -I 23,26</code></li></ul></li></ul>

<ul><li>To execute tests whose names contain e.g. <code>StrToLwr</code>, run:<br>
<ul><li><code>ctest -R StrToLwr</code></li></ul></li></ul>

<ul><li>To enable output, add -V to the mix, e.g.<br>
<ul><li><code>ctest -I 23,26 -V</code></li></ul></li></ul>

<h3>Sending Results to the Dashboard</h3>

To run tests which upload their results and output to our <a href='http://dash.maidsafe.net/index.php?project=maidsafe-dht'>dashboard</a>, simply build the target <code>Experimental</code> in your chosen IDE or run <code>make Experimental</code> from the maidsafe-dht build directory.