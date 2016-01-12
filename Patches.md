# Introduction #

This section is dedicated to giving some guidelines that will help contributors minimise their suffering with our requirements =).

# Guidelines #

  * Generate your patch by running `svn diff > myname.patch` in the svn root directory.

  * The patch file should be sent to <a href='mailto:dev@maidsafe.net?subject=maidsafe-dht%20Patch'>dev@maidsafe.net</a>

  * The level of warnings specified in the CMakeList is the one we want to maintain, therefore, make sure that no new warnings appear when compiling.

  * Run a `make Experimental` and ensure all tests pass before submitting the patch. This will leave proof on our <a href='http://dash.maidsafe.net/index.php?project=maidsafe-dht'>dashboard</a> that the code ran properly at least once on one machine.

  * We try as far as possible to adhere to the <a href='http://google-styleguide.googlecode.com/svn/trunk/cppguide.xml'>Google C++ Style Guide</a>. To that end, some of the tests in the suite run the <a href='http://www.python.org/download'>Python</a> script <a href='http://google-styleguide.googlecode.com/svn/trunk/cpplint/cpplint.py'>cpplint.py</a> to check the coding style, so you will need to have the <a href='http://www.python.org/download'>Python</a> interpreter installed to run it. Code submitted must pass those tests as well.

  * If new features are added, tests must be provided to verify the correct functionality and existing tests must be updated accordingly.

  * No patches with code requiring RTTI will be accepted.

  * We anticipate no significant increase in the number of maidsafe-dht dependencies.  However if your patch does introduce further dependencies, we discourage the use of non-approved Boost libraries.

  * Items in the <a href='http://code.google.com/p/maidsafe-dht/wiki/TODO'>TODO list</a> are first in line for consideration.