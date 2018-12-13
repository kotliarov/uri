#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE query_grammar

#include <boost/test/unit_test.hpp>

#include <uri/parser.hpp>

#include <map>
#include <string>
#include <vector>
#include <fstream>

namespace qi = boost::spirit::qi;
using Iterator = std::string::const_iterator;

// Parse URI query string and store collection of
// key, value pairs into an associative container - std::map.
BOOST_AUTO_TEST_CASE(query_grammar)
{
    std::string text{"pages=all&orientation=landscape&printer=a%3Da"};
    Iterator s = text.begin();
    Iterator e = text.end();

    std::map<std::string, std::string> dict; // Container for key, value pairs.
    uri::query_grammar<Iterator> query;
    bool rc = qi::parse(s, e, query, dict);

    BOOST_CHECK_EQUAL(rc, true);
    BOOST_CHECK(s == e);

    BOOST_CHECK_EQUAL(3, dict.size());
    BOOST_CHECK_EQUAL("all", dict.at("pages"));
    BOOST_CHECK_EQUAL("landscape", dict.at("orientation"));
    BOOST_CHECK_EQUAL("a%3Da", dict.at("printer"));
}
