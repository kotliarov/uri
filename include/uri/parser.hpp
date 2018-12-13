#include <iostream>
#include <string>
#include <map>

#include <boost/spirit/include/qi.hpp>
#include <boost/spirit/include/phoenix_core.hpp>
#include <boost/spirit/include/phoenix_operator.hpp>
#include <boost/spirit/include/phoenix_object.hpp>
#include <boost/fusion/include/adapt_struct.hpp>
#include <boost/fusion/include/boost_array.hpp>
#include <boost/fusion/include/std_pair.hpp>


namespace uri
{

using dictionary_t = std::map<std::string, std::string>;
using pair_t = std::pair<std::string, std::string>;

struct authority_t
{
    pair_t userinfo;
    std::string host;
    uint32_t port=0;
};

std::ostream& operator << (std::ostream& oss, ::uri::authority_t const& value)
{
    oss << '\n'
        << "authority { "
        << '\n'
        << "    userinfo {"
        << '\n'
        << "          username=" << value.userinfo.first
        << '\n'
        << "          password=" << value.userinfo.second
        << '\n'
        << "    }"
        << '\n'
        << "    host=" << value.host
        << '\n'
        << "    port=" << value.port
        << '\n'
        << "}"
        << '\n';
    return oss;
}
struct uri_t
{
    std::string scheme;
    authority_t auth;
    std::string path;
    dictionary_t query;
};

std::ostream& operator << (std::ostream& oss, ::uri::uri_t const& value)
{
    oss << '\n'
        << "uri{ "
        << '\n'
        << "    schema=" << value.scheme
        << '\n'
        << value.auth
        << '\n'
        << "    path=" << value.path
        << '\n'
        << "    query = {";

    for (auto const& kv: value.query) {
        oss << '\n'
            << "\t" << kv.first << "=" << kv.second;

    }

    oss << '\n'
        << "    }" // query
        << '\n'
        << "}"
        << '\n';
    return oss;
}

} // namespace

BOOST_FUSION_ADAPT_STRUCT(
    uri::authority_t,
    (uri::pair_t, userinfo)
    (std::string, host)
    (uint32_t, port)
)

BOOST_FUSION_ADAPT_STRUCT(
    uri::uri_t,
    (std::string, scheme)
    (uri::authority_t, auth)
    (std::string, path)
    (uri::dictionary_t, query)
)


namespace uri
{

namespace qi = boost::spirit::qi;

//---------------------------------------------------
//
// URI RFC
//
// https://tools.ietf.org/html/rfc3986#section-3.2.1
//

template <typename Iterator>
struct sub_delims_grammar : qi::grammar<Iterator, char()> {

    sub_delims_grammar(): sub_delims_grammar::base_type(sub_delims)
    {
        sub_delims %=  qi::char_("!$&\\()*+,;=");
    }

    qi::rule<Iterator, char()> sub_delims;
};

template <typename Iterator>
struct pct_encoded_grammar : qi::grammar<Iterator, std::string()> {

    pct_encoded_grammar(): pct_encoded_grammar::base_type(pct_encoded)
    {
        pct_encoded %= qi::char_('%') >> qi::xdigit >> qi::xdigit;
    }

    qi::rule<Iterator, std::string()> pct_encoded;
};

template <typename Iterator>
struct unreserved_grammar : qi::grammar<Iterator, char()> {

    unreserved_grammar(): unreserved_grammar::base_type(unreserved)
    {
        unreserved %=   qi::alnum |
                        qi::char_("-._~");
    }

    qi::rule<Iterator, char()> unreserved;
};

template <typename Iterator>
struct pchar_grammar : qi::grammar<Iterator, std::string()>
{
    pchar_grammar() : pchar_grammar::base_type(pchar)
    {
        pchar = unreserved  |
                pct_encoded |
                sub_delims  |
                qi::char_(":@");
    }

    qi::rule<Iterator, std::string()> pchar;
    sub_delims_grammar<Iterator> sub_delims;
    pct_encoded_grammar<Iterator> pct_encoded;
    unreserved_grammar<Iterator> unreserved;
};

template <typename Iterator>
struct scheme_grammar : qi::grammar<Iterator, std::string()>
{
    scheme_grammar() : scheme_grammar::base_type(scheme)
    {
        scheme %= qi::alpha >> *(qi::alnum | qi::char_("+-."));
    }
    qi::rule<Iterator, std::string()>  scheme;
};

template <typename Iterator>
struct authority_grammar : qi::grammar<Iterator, ::uri::authority_t()>
{
    authority_grammar() : authority_grammar::base_type(authority)
    {
        // octet is a rule to parse (250-255 | 200-249 | 100-199 | 10-99 | 0-9)
        octet = qi::string("25") >> qi::char_("0-5") |
                qi::char_('2') >> qi::char_("0-4")  >> qi::digit |
                qi::char_('1') >> qi::digit  >> qi::digit |
                qi::char_("1-9") >> qi::digit |
                qi::digit;

        ipv4address = octet
                      >> qi::char_('.') >> octet
                      >> qi::char_('.') >> octet
                      >> qi::char_('.') >> octet;

        reg_name  = *(unreserved |
                      pct_encoded |
                      sub_delims);

        host = reg_name |
               ipv4address;

        userinfo = reg_name >> -(':' >> reg_name);
        port = qi::uint_;
        authority = -(userinfo >> '@') >> host >> -(':' >> port);
    }

    sub_delims_grammar<Iterator> sub_delims;
    pct_encoded_grammar<Iterator> pct_encoded;
    unreserved_grammar<Iterator> unreserved;

    qi::rule<Iterator, std::string()>         octet;
    qi::rule<Iterator, std::string()>         ipv4address;
    qi::rule<Iterator, std::string()>         reg_name;
    qi::rule<Iterator, pair_t()>              userinfo;
    qi::rule<Iterator, std::string()>         host;
    qi::rule<Iterator, uint32_t>              port;
    qi::rule<Iterator, ::uri::authority_t()>  authority;
};

template <typename Iterator>
struct path_grammar : qi::grammar<Iterator, std::string()>
{
    path_grammar() : path_grammar::base_type(path)
    {
        segment_nz_nc = +(unreserved | pct_encoded | sub_delims | qi::char_('@'));
        path_abempty  = *(qi::char_('/') >> *pchar);
        path_absolute = qi::char_('/')  >> -(+pchar >> *(qi::char_('/') >>  *pchar));
        path_noscheme = segment_nz_nc >> *( qi::char_('/') >> *pchar);
        path_rootless = +pchar >> *( qi::char_('/') >> *pchar);
        path_empty    = qi::eps;

        path = path_abempty |
               path_absolute |
               path_noscheme |
               path_rootless |
               path_empty;
    }

    sub_delims_grammar<Iterator> sub_delims;
    pct_encoded_grammar<Iterator> pct_encoded;
    unreserved_grammar<Iterator> unreserved;
    pchar_grammar<Iterator> pchar;

    qi::rule<Iterator, std::string()>  segment_nz_nc;
    qi::rule<Iterator, std::string()>  path_abempty;
    qi::rule<Iterator, std::string()>  path_absolute;
    qi::rule<Iterator, std::string()>  path_noscheme;
    qi::rule<Iterator, std::string()>  path_rootless;
    qi::rule<Iterator, std::string()>  path_empty;
    qi::rule<Iterator, std::string()>  path;
};

template <typename Iterator>
struct query_grammar : qi::grammar<Iterator, dictionary_t()>
{
    query_grammar() : query_grammar::base_type(query)
    {
        key = qi::alpha >> *(qi::alnum | qi::char_("-._"));
        value = +(unreserved | pct_encoded);
        pair = key >> '=' >> value;
        query =  pair >> *('&' >> pair);
    }

    pct_encoded_grammar<Iterator> pct_encoded;
    unreserved_grammar<Iterator> unreserved;

    qi::rule<Iterator, std::string()>  key;
    qi::rule<Iterator, std::string()>  value;
    qi::rule<Iterator, std::pair<std::string, std::string>()>  pair;
    qi::rule<Iterator, dictionary_t()>  query;
};

template <typename Iterator>
struct uri_grammar : qi::grammar<Iterator, ::uri::uri_t()>
{

    uri_grammar() : uri_grammar::base_type(uri)
    {
        uri %= scheme
                >> qi::lit("://")
                >> -auth
                >> path
                >> -('?' >> query);
    }

    scheme_grammar<Iterator> scheme;
    authority_grammar<Iterator> auth;
    query_grammar<Iterator> query;
    path_grammar<Iterator> path;
    qi::rule<Iterator, ::uri::uri_t()> uri;
};

} // namespace

#if 0
namespace qi = boost::spirit::qi;

int main(int argc, char** argv)
{
    using Iterator = std::string::const_iterator;
    uri::scheme_grammar<Iterator> g;

    std::string text{"KmerCache"};
    std::string::const_iterator s = text.begin();
    std::string::const_iterator e = text.end();

    std::string value;
    std::string scheme;
    bool r = qi::parse(s, e, g, value);
    std::cout << value;


    //-- query
    uri::query_grammar<Iterator> query;
    std::string q{"?a=1&abc=foo&name=John"};
    std::map<std::string, std::string> dict;
    s = q.begin();
    e = q.end();
    qi::parse(s, e, query, dict);


    //-- authority
    uri::authority_grammar<Iterator> auth_grammar;
    {{
        std::string auth{"www.service.net:871"};
        uri::authority_t auth_val;
        s = auth.begin();
        e = auth.end();
        qi::parse(s, e, auth_grammar, auth_val);
        std::cout << auth_val;
    }}

   {{
        std::vector<std::string> coll = {
            "https://alex@www.yahoo.net/this/is/a/resource?foo=Moo&boo=aa%34bb",
            "https://alex@www.yahoo.net/this/is/a/resource/?foo=Moo&boo=aa%34bb",
            "https://alex@www.yahoo.net/?foo=Moo&boo=aa%34bb",
            "https://alex@www.yahoo.net?foo=Moo&boo=aa%34bb",
            "https://alex:secret@www.yahoo.net?foo=Moo&boo=aa%34bb",
            "https://127.0.0.1:8001?foo=Moo&boo=aa%34bb",
            "file:///bin/etc",
            "file://host/bin/etc?foo=Moo",
            "file:///?foo=Moo",
        };

        for (auto const& text: coll) {
            uri::uri_grammar<Iterator> uri_grammar;

            uri::uri_t val;
            s = text.begin();
            e = text.end();
            qi::parse(s, e, uri_grammar, val);
            std::cout << '\n'
                      << "=== Text: " << text
                      << '\n';
            std::cout << val;
        }

    }}
}
#endif
