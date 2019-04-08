#include "rsa.h"
#include <cstring>
#include <iostream>
#include <fstream>
#include <stdexcept>

using namespace std;

RSAKeyParser::RSAKeyParser(const string& file_name, FileType file_type)
    : file_stream(0)
{
    open(file_name, file_type);
}

void RSAKeyParser::open(const string& file_name, FileType file_type)
{
    file_stream = new ifstream(file_name.c_str());
    this->file_type = file_type;
    if ( file_type == base64 ) {
        if ( read_line() != "-----BEGIN RSA PRIVATE KEY-----" )
            throw runtime_error("no header line");
        string bytes;
        unsigned cur_bit_count = 0;
        unsigned cur_bits = 0;
        for ( ;; ) {
            string line = read_line();
            if ( line == "-----END RSA PRIVATE KEY-----" )
                break;
            for ( size_t i = 0; i < line.size(); ++i ) {
            	char c = line[i];
                unsigned v;
                if ( c >= 'A' && c <= 'Z' ) {
                    v = c-'A';
                }
                else if ( c >= 'a' && c <= 'z' ) {
                    v = c-'a' + 26;
                }
                else if ( c >= '0' && c <= '9' ) {
                    v = c-'0' + 52;
                }
                else if ( c == '+' ) {
                    v = 62;
                }
                else if ( c == '/' ) {
                    v = 63;
                }
                else if ( c == '=' ) {
                    continue;
                }
                else {
                    throw runtime_error("bad base64 char: "+line);
                }
                cur_bits = (cur_bits << 6)+v;
                cur_bit_count += 6;
                if ( cur_bit_count >= 8 ) {
                    bytes += char(cur_bits >> (cur_bit_count-8));
                    cur_bit_count -= 8;
                }
            }
        }
        delete file_stream;
        file_stream = new istringstream(bytes);
        this->file_type = asn1;
    }
}

RSAKeyParser::~RSAKeyParser()
{
	close();
}

void RSAKeyParser::close()
{
	delete file_stream;
	file_stream = 0;
}

static
string trim(string s, char c = ' ')
{
    size_t p1 = s.find_first_not_of(c);
    size_t p2 = p1 == string::npos? s.size(): s.find_last_not_of(c)+1;
    return s.substr(p1, p2-p1);
}

string RSAKeyParser::read_line()
{
    string line;
    if ( !getline(*file_stream, line) )
        throw runtime_error("read failed");
    return trim(line, '\r');
}

uint32_t RSAKeyParser::read_asn1_length()
{
    uint8_t len = file_stream->get();
    if ( len < 0x80 ) {
        return len;
    }
    if ( len > 0x80 && len <= 0x84 ) {
        uint32_t ret = 0;
        for ( uint8_t i = 0x80; i < len; ++i ) {
            ret = (ret << 8) + uint8_t(file_stream->get());
        }
        return ret;
    }
    throw runtime_error("indefinite length not supported");
}


enum TagType {
    tagSequence,
    tagInteger
};

pair<TagType, string> get_decoded_element(const string& line)
{
    size_t p = line.find(':');
    if ( p == string::npos )
        throw runtime_error("pos colon not found");
    size_t p1 = line.find(':', p+1);
    if ( p1 == string::npos )
        throw runtime_error("type colon not found");
    size_t p2 = line.find(':', p1+1);
    pair<TagType, string> ret;
    string type = trim(line.substr(p1+1, p2-p1-1));
    if ( p2 != string::npos )
        ret.second = line.substr(p2+1);
    if ( type == "SEQUENCE" ) {
        ret.first = tagSequence;
    }
    else if ( type == "INTEGER" ) {
        ret.first = tagInteger;
    }
    else {
        throw runtime_error("Unknown tag type: "+type);
    }
    return ret;
}

void RSAKeyParser::open_sequence()
{
    if ( file_type == asn1 ) {
        if ( file_stream->get() != 0x30 )
            throw runtime_error("SEQUENCE expected");
        read_asn1_length();
    }
    else {
        if ( get_decoded_element(read_line()).first != tagSequence )
            throw runtime_error("SEQUENCE expected");
    }
}

void RSAKeyParser::close_sequence()
{
}

RSAFullInt RSAKeyParser::get_integer()
{
    if ( file_type == asn1 ) {
        if ( file_stream->get() != 0x02 )
            throw runtime_error("INTEGER expected");
        uint32_t len = read_asn1_length();
        RSAFullInt v;
        for ( uint32_t i = 0; i < len; ++i ) {
            uint8_t b = file_stream->get();
            if ( b ) {
                v.set_byte(len-1-i, b);
            }
        }
        return v;
    }
    else {
    	pair<TagType, string> e = get_decoded_element(read_line());
        if ( e.first != tagInteger )
            throw runtime_error("INTEGER expected");
        RSAFullInt v;
        v.from_hex_string(e.second.c_str());
        return v;
    }
}

RSAPrivateKey::RSAPrivateKey(const string& file_name, RSAKeyParser::FileType file_type)
{
    RSAKeyParser in(file_name, file_type);
    in.open_sequence();
    if ( in.get_integer() != RSAFullInt() )
        throw runtime_error("key version is not zero");
    modulus = in.get_integer();
    publicExponent = in.get_integer();
    privateExponent = in.get_integer();
    prime1 = in.get_integer();
    prime2 = in.get_integer();
    exponent1 = in.get_integer();
    exponent2 = in.get_integer();
    coefficient = in.get_integer();
    in.close_sequence();
}
