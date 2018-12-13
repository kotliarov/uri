#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE delimited_sequence

#include <boost/test/unit_test.hpp>

#include <boost/spirit/include/qi.hpp>
#include <boost/fusion/include/std_pair.hpp>

#include <string>
#include <vector>

namespace qi = boost::spirit::qi;
using Iterator = std::string::const_iterator;

// Parse delimited sequence of tokens
// and store tokens into a container.
BOOST_AUTO_TEST_CASE(delimited_sequence) {
    std::string text{"one&two&three&four"};
    Iterator s = text.begin();
    Iterator e = text.end();

    std::vector<std::string> tokens; // Container for tokens.
    bool rc = qi::parse(s, e, +qi::alnum >> *('&' >> +qi::alnum), tokens);

    BOOST_CHECK_EQUAL(rc, true);
    BOOST_CHECK(s == e);

    BOOST_CHECK_EQUAL(4, tokens.size());
    BOOST_CHECK_EQUAL("one", tokens[0]);
    BOOST_CHECK_EQUAL("two", tokens[1]);
    BOOST_CHECK_EQUAL("three", tokens[2]);
    BOOST_CHECK_EQUAL("four", tokens[3]);
}

