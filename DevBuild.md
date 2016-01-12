  * [Introduction](#Introduction.md)
  * [Project Requirements](#Project_Requirements.md)
    * [Essential](#Essential.md)
    * [Recommended, non-essential](#Recommended,_non-essential.md)
    * [Creating the MinGW Build Environment in Windows](#Creating_the_MinGW_Build_Environment_in_Windows.md)
  * [Making and Installing maidsafe-dht](#Making_and_Installing_maidsafe-dht.md)
    * [Building on Linux](#Building_on_Linux.md)
    * [Building on Windows - MSVC](#Building_on_Windows_-_MSVC.md)
    * [Building on Windows - MinGW](#Building_on_Windows_-_MinGW.md)
    * [Building on OSX](#Building_on_OSX.md)

# Introduction #
This page explains how to build the maidsafe-dht project and details prerequisites to building the project.  For Windows users, the project can be generated for MSVC, or in a MinGW environment for e.g. CodeBlocks.
# Project Requirements #
### Essential ###
  * [CMake (minimum version 2.8)](http://www.cmake.org/cmake/resources/software.html) To build the project, CMake must be installed and in your path.<br><br>
<ul><li><a href='http://sourceforge.net/projects/boost/files/boost'>Boost (minimum version 1-40)</a> The libraries should be built in static, multi-threaded, release mode. Required boost components are:<br>
<ul><li>date_time<br>
</li><li>filesystem<br>
</li><li>program_options<br>
</li><li>regex<br>
</li><li>system<br>
</li><li>test<br>
</li><li>thread<br>
</li></ul></li></ul><blockquote>If using <a href='http://www.boost.org/doc/libs/1_42_0/more/getting_started/windows.html#get-bjam'>bjam</a> to build boost, the following commands run from a freshly unzipped boost root directory should work:<br>
<h4>Unix</h4>
<ul><li><code>./bootstrap.sh</code> (creates the bjam executable in the boost directory which is used to build and install the boost libraries and headers)<br>
</li><li><code>mkdir Build</code> (creates a directory to hold the boost libraries prior to installing them)<br>
</li><li><code>sudo ./bjam toolset=gcc variant=release link=static threading=multi runtime-link=shared --build-dir=Build --layout=system --with-date_time --with-filesystem --with-program_options --with-regex --with-system --with-test --with-thread install --prefix=/usr stage</code> (builds the libraries, copies them to <code>/usr/lib</code> and copies the headers to <code>/usr/include</code>)<br>
</li></ul><h4>Windows - MSVC</h4>
<ul><li><code>bootstrap</code> (creates the bjam executable in the boost directory which is used to build the boost libraries and headers)<br>
</li><li><code>mkdir Build</code> (creates a directory to hold the boost libraries prior to installing them)<br>
</li><li><code>bjam toolset=msvc link=static threading=multi runtime-link=shared --build-dir=Build --layout=versioned --with-date_time --with-filesystem --with-program_options --with-regex --with-system --with-test --with-thread define=_BIND_TO_CURRENT_MFC_VERSION=1 define=_BIND_TO_CURRENT_CRT_VERSION=1 stage</code> (builds the libraries)<br>
</li></ul><h4>Windows - MinGW</h4>
<ul><li><code>bootstrap</code> (creates the bjam executable in the boost directory which is used to build the boost libraries and headers)<br>
</li><li><code>mkdir Build</code> (creates a directory to hold the boost libraries prior to installing them)<br>
</li><li><code>bjam toolset=gcc variant=release link=static threading=multi runtime-link=shared --build-dir=Build --layout=versioned --with-date_time --with-filesystem --with-program_options --with-regex --with-system --with-test --with-thread install --prefix=c:\usr stage</code> (builds the libraries, copies them to <code>c:\usr\lib</code> and copies the headers to <code>c:\usr\include</code>)<br>
</li></ul></blockquote><ul><li><a href='http://code.google.com/p/googletest/downloads/list'>Google Test (minimum version 1.5)</a><br>If using MSVC, ensure you build Gtest from the solution <code>gtest-md.sln</code> and not <code>gtest.sln</code> or the Gtest libraries will link to Microsoft C runtime libraries which are incompatible with those used elsewhere in maidsafe-dht.  Also, ensure Debug and Release targets are both built.<br><br>
</li><li><a href='http://code.google.com/p/protobuf/downloads/list'>Google Protocol Buffers (minimum version 2.1.0)</a><br>Again, if using MSVC, ensure Debug and Release targets are both built.<br><br></li></ul>

<h3>Recommended, non-essential</h3>
<ul><li><a href='http://www.python.org/download'>Python</a> (allows a style checker to run)<br><br>
</li><li><a href='http://code.google.com/p/google-glog/downloads/list'>Google-glog</a> (allows logging)<br>If using MSVC, ensure you build the target <code>libglog_static</code> in both Debug and Release modes.  Glog cannot currently be built on Windows using MinGW.<br><br>
</li><li><a href='http://www.codeblocks.org/downloads'>CodeBlocks IDE</a> (a CodeBlocks project is created after running cmake unless MSVC is selected as the cmake Generator)<br><br></li></ul>

<h3>Creating the MinGW Build Environment in Windows</h3>
If you intend to use MSVC, then this section is not applicable.  Otherwise, if you're building in Windows, you'll need to create a Linux-esque environment in which to make and install the prerequisites (with the exception of the Boost libraries, since <a href='http://www.boost.org/doc/libs/1_42_0/more/getting_started/windows.html#get-bjam'>bjam</a> can be run from a Windows command terminal).<br>
This can run alongside a standard Visual Studio implementation, since it uses <code>c:\usr\lib</code> rather than MSVC's <code>c:\lib</code> so this other environment won't mess with your libraries. If you decide to install the libraries and headers to a location other than <code>c:\usr</code>, cmake will require these paths entered as variables when running the cmake command.<br>
To help create this environment we have bundled the following installers into this <a href='http://maidsafe-dht.googlecode.com/files/wintools_02.zip'>zipped folder</a>.<br>
<ul><li><a href='http://www.cmake.org/cmake/resources/software.html'>CMake 2.8.0</a>
</li><li><a href='http://www.codeblocks.org/downloads'>CodeBlocks 8.02</a>
</li><li><a href='http://tdragon.net/recentgcc'>TDM's GCC/MinGW</a>
</li><li><a href='http://www.mingw.org/wiki/msys'>MSYS 1.0.11</a>
</li><li><a href='http://nsis.sourceforge.net/Download'>NSIS 2.45</a> (This will allow you to build an installer)<br>
To create the Linux environment in Windows:<br>
</li></ul><ol><li>Download the <a href='http://maidsafe-dht.googlecode.com/files/wintools_02.zip'>zipped bundle</a> or individual installers above.<br>
</li><li>Install tdm-mingw and add it to your path (select this option during install).<br>
</li><li>Install MSYS. When asked about the interface with MinGW, select YES, then enter <code>c:\MinGW</code> as the location.<br>
Running MSYS now allows you to make and install the above required libraries (<a href='http://code.google.com/p/googletest/downloads/list'>Google Test</a>, <a href='http://code.google.com/p/protobuf/downloads/list'>Google Protocol Buffers</a>, <a href='http://code.google.com/p/google-glog/downloads/list'>Google-glog</a>) as though in a Linux environment.<br>
Proceed to build the libraries. In most cases this will usually involve <code>cd</code> to the library's root, running <code>./configure --prefix=/c/usr</code> then <code>make</code> then <code>make install</code>.</li></ol>

<b>Note</b>: The MSYS equivalent of e.g. "<code>c:\dir</code>" is "<code>/c/dir</code>". Please also be aware that MSYS does not handle spaces in paths so you MUST build this in a path with no spaces (e.g. not "<code>C:\Documents and Settings</code>").<br><br>

<h1>Making and Installing maidsafe-dht</h1>

<h3>Building on Linux</h3>

<ol><li>Download the <a href='http://code.google.com/p/maidsafe-dht/source/checkout'>maidsafe-dht src</a>.<br>
</li><li><code>cd</code> to build dir for Linux matching the build type required (<code>build/Linux/Debug</code>, <code>build/Linux/Release</code>, etc.)<br>
</li><li>Run <code>cmake ../../.. -G"CodeBlocks - Unix Makefiles"</code>
</li><li>Run <code>make</code> (this will make all). Other options:<br>
<ul><li>Run <code>make Experimental</code> to configure, build, test and upload to our <a href='http://dash.maidsafe.net/index.php?project=maidsafe-dht'>dashboard</a>.<br>
</li><li>Run <code>make package</code> to create auto rpm or deb.<br>
</li><li>Run <code>make install</code> to install the maidsafe-dht library to <code>/usr/lib</code> and headers to <code>/usr/include</code>.</li></ul></li></ol>

<h3>Building on Windows - MSVC</h3>

<ol><li>Download the <a href='http://code.google.com/p/maidsafe-dht/source/checkout'>maidsafe-dht src</a>.<br>
</li><li>Open a Windows command terminal and <code>cd</code> to build dir for Windows (<code>build\Win_MSVC</code>)<br>
</li><li>Run one of the following commands appropriate to your MSVC version:<br>
<ul><li><code>cmake ..\.. -G"Visual Studio 6"</code>
</li><li><code>cmake ..\.. -G"Visual Studio 7"</code>
</li><li><code>cmake ..\.. -G"Visual Studio 7 .NET 2003"</code>
</li><li><code>cmake ..\.. -G"Visual Studio 8 2005"</code>
</li><li><code>cmake ..\.. -G"Visual Studio 8 2005 Win64"</code>
</li><li><code>cmake ..\.. -G"Visual Studio 9 2008"</code>
</li><li><code>cmake ..\.. -G"Visual Studio 9 2008 Win64"</code>
</li><li><code>cmake ..\.. -G"Visual Studio 10"</code>
</li><li><code>cmake ..\.. -G"Visual Studio 10 Win64"</code>
This will create an MSVC solution <code>build\Win_MSVC\maidsafe_dht.sln</code> which will allow you to make all the targets from within the chosen MSVC IDE.  Once the solution is built, you can run <code>build\Win_MSVC\extract_includes.bat</code> to create a directory <code>build\Win_MSVC\include</code> which will contain the public headers.  Building the target <code>Experimental</code> will build the full test suite, run it and upload the results to our <a href='http://dash.maidsafe.net/index.php?project=maidsafe-dht'>dashboard</a>.</li></ul></li></ol>

<h3>Building on Windows - MinGW</h3>

<ol><li>Download the <a href='http://code.google.com/p/maidsafe-dht/source/checkout'>maidsafe-dht src</a>.<br>
</li><li>Open a Windows command terminal.<br>
</li><li><code>cd</code> to build dir for Windows matching the build type required (<code>build\Win_MinGW\Debug</code>, <code>build\Win_MinGW\Release</code>, etc.)<br>
</li><li>Run <code>cmake ..\..\.. -G"CodeBlocks - MinGW Makefiles"</code>. This will create a CodeBlocks project e.g. <code>build\Win_MinGW\Debug\maidsafe-dht.cbp</code> which will allow you to make and install all the targets from within the CodeBlocks IDE.<br>
If MinGW was added to your path, you should also be able to build the targets from a Windows command terminal:<br>
</li></ol><ul><li>Run <code>mingw32-make</code> to make all targets.<br>
</li><li>Run <code>mingw32-make Experimental</code> to configure, build, test and upload to our <a href='http://dash.maidsafe.net/index.php?project=maidsafe-dht'>dashboard</a>.<br>
</li><li>Run <code>mingw32-make package</code> to create an installer.<br>
</li><li>Run <code>mingw32-make install</code> to install the maidsafe-dht library to <code>c:\usr\lib</code> and headers to <code>c:\usr\include</code>.</li></ul>

<h3>Building on OSX</h3>

<ol><li>Download the <a href='http://code.google.com/p/maidsafe-dht/source/checkout'>maidsafe-dht src</a>.<br>
</li><li><code>cd</code> to build dir for OSX matching the build type required (<code>build/OSX/Debug</code>, <code>build/OSX/Release</code>, etc.)<br>
</li><li>Run <code>cmake ../../.. -G"CodeBlocks - Unix Makefiles"</code>
</li><li>Run <code>make</code> (this will make all). Other options:<br>
<ul><li>Run <code>make Experimental</code> to configure, build, test and upload to our <a href='http://dash.maidsafe.net/index.php?project=maidsafe-dht'>dashboard</a>.<br>
</li><li>Run <code>make package</code> to create auto rpm or deb.<br>
</li><li>Run <code>make install</code> to install the maidsafe-dht library to <code>/usr/lib</code> and headers to <code>/usr/include</code>.