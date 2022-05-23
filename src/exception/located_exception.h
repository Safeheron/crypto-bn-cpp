/*
 * Copyright 2017-2022 Safeheron Inc. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.safeheron.com/opensource/license.html
 */

#ifndef SAFEHERON_LOCATED_EXCEPTION_H
#define SAFEHERON_LOCATED_EXCEPTION_H

#define EXCEPTION_FILE_PATH_BUF_SIZE 48
#define EXCEPTION_FUNC_NAME_BUF_SIZE 24

#include <iostream>
#include <fstream>
#include <sstream>
#include <string.h>
#include <stdexcept>

namespace safeheron{
namespace exception{

//! LocatedException class thrown when a method fails, with message (file_path, func, line_num, internal_code)
class LocatedException : public std::exception
{
public:
    explicit LocatedException(const char * file_path, int line_num, const char * func, long internal_code) {
        memset(file_path_, 0, EXCEPTION_FILE_PATH_BUF_SIZE);
        memset(func_, 0, EXCEPTION_FUNC_NAME_BUF_SIZE);

        int src_offset = 0;
        size_t src_len = strlen(file_path);
        if(src_len >= EXCEPTION_FILE_PATH_BUF_SIZE){
            src_offset = src_len - EXCEPTION_FILE_PATH_BUF_SIZE + 1;
            src_len = EXCEPTION_FILE_PATH_BUF_SIZE - 1;
        }
        strncpy(file_path_, file_path + src_offset, src_len);
        file_path_[EXCEPTION_FILE_PATH_BUF_SIZE - 1] = 0;

        src_offset = 0;
        src_len = strlen(func);
        if(src_len >= EXCEPTION_FUNC_NAME_BUF_SIZE){
            src_offset = src_len - EXCEPTION_FUNC_NAME_BUF_SIZE + 1;
            src_len = EXCEPTION_FUNC_NAME_BUF_SIZE - 1;
        }
        strncpy(func_, func + src_offset, src_len);
        func_[EXCEPTION_FUNC_NAME_BUF_SIZE - 1] = 0;

        line_num_ = line_num;

        internal_code_ = internal_code;
    }

    virtual const char* what() const throw () {
        return file_path_;
    }

    // Use function detail() instead of what()
    virtual std::string detail() const {
        std::ostringstream ostr;
        ostr << file_path_ << ":" << line_num_ << "  " << func_ << "  code(" << internal_code_ << ")";
        return ostr.str();
    }

public:
    char file_path_[EXCEPTION_FILE_PATH_BUF_SIZE];
    char func_[EXCEPTION_FUNC_NAME_BUF_SIZE];
    int line_num_;
    long internal_code_;
};

};
};

#endif // SAFEHERON_LOCATED_EXCEPTION_H
