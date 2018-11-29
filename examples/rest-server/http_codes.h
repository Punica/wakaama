/*
 * MIT License
 *
 * Copyright (c) 2017 8devices
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#ifndef HTTP_CODES_H
#define HTTP_CODES_H

#define HTTP_200_OK                 200
#define HTTP_201_CREATED            201
#define HTTP_202_ACCEPTED           202
#define HTTP_204_NO_CONTENT         204

#define HTTP_400_BAD_REQUEST        400
#define HTTP_401_UNAUTHORIZES       401
#define HTTP_403_FORBIDDEN          403
#define HTTP_404_NOT_FOUND          404
#define HTTP_405_METHOD_NOT_ALLOWED 405
#define HTTP_406_NOT_ACCEPTABLE     406
#define HTTP_408_REQUEST_TIMEOUT    408
#define HTTP_409_CONFLICT           409
#define HTTP_410_GONE               410
#define HTTP_413_PAYLOAD_TOO_LARGE  413
#define HTTP_415_UNSUPPORTED_MEDIA_TYPE 415

#define HTTP_500_INTERNAL_ERROR     500
#define HTTP_501_NOT_IMPLEMENTED    501

#endif // HTTP_CODES_H

