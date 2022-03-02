/**
 *@brief MyFile
 */

#ifndef SAFEHERON_EXCEPTION_H
#define SAFEHERON_EXCEPTION_H

#define EXCEPTION_FILE_PATH_BUF_SIZE 48
#define EXCEPTION_FUNC_NAME_BUF_SIZE 24

#include "located_exception.h"

namespace safeheron{
namespace exception{

///@brief BadAllocException class thrown when a memory allocation fails
class BadAllocException : public LocatedException
{
public:
    explicit BadAllocException(const char * file_path, int line_num, const char * func, long internal_code) : LocatedException(file_path, line_num, func, internal_code) {}
};

//! RandomSourceException class thrown when a generation of random bytes fails
class RandomSourceException : public LocatedException
{
public:
    explicit RandomSourceException(const char * file_path, int line_num, const char * func, long internal_code) : LocatedException(file_path, line_num, func, internal_code) {}
};

//! OpensslException class thrown when a exception for error code in openssl library
class OpensslException : public LocatedException
{
public:
    explicit OpensslException(const char * file_path, int line_num, const char * func, long internal_code) : LocatedException(file_path, line_num, func, internal_code) {}
};

}
}


#endif // SAFEHERON_EXCEPTION_H
