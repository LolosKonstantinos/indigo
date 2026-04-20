/*Copyright (c) 2026 Lolos Konstantinos

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#ifndef INDIGO_ERRORS_H
#define INDIGO_ERRORS_H

#define INDIGO_SUCCESS 0
#define INDIGO_ERROR 1

//positive values are for errors the programmer or the system caused
#define INDIGO_ERROR_SYS_FAIL                 2
#define INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR  3
#define INDIGO_ERROR_INVALID_PARAM            4
#define INDIGO_ERROR_INVALID_STATE            5 //this is a bug state of the application, a "bug state" essentially
#define INDIGO_ERROR_UNSUPPORTED              6
#define INDIGO_ERROR_WINLIB_ERROR             7
#define INDIGO_ERROR_SODIUM_ERROR             8
#define INDIGO_ERROR_TIMEOUT                  9
#define INDIGO_ERROR_FILE_NOT_FOUND           10
#define INDIGO_ERROR_NO_ADDRESS_FOUND         11 //this error is for when there is no available active address
#define INDIGO_ERROR_WINSOCK2_NOT_INITIALIZED 12
#define INDIGO_ERROR_NETWORK_SUBSYS_DOWN      13 //serious error we need to terminate the application
#define INDIGO_ERROR_CAN_NOT_OPEN_FILE        14
#define INDIGO_ERROR_BUG                      15
#define INDIGO_ERROR_NETWORK_RESET            16 //can be recovered from, renew the sockets, and any overlapped struct
#define INDIGO_ERROR_NO_SYS_RESOURCES         17 //recoverable, just wait, the os buffers are full
#define INDIGO_ERROR_FILE_NOT_AUTHORIZED      18
#define INDIGO_ERROR_RESOURCE_NOT_FOUND       19

//negative values are for errors the user or a peer caused
#define INDIGO_ERROR_INVALID_INPUT      (-1)
#define INDIGO_ERROR_INCOMPATIBLE_FILE  (-2)
#define INDIGO_ERROR_FALSE_SIGNATURE    (-3)
#define INDIGO_ERROR_FALSE_KEY          (-4)
#define INDIGO_ERROR_PEER_DISCONNECTED  (-5)
#define INDIGO_ERROR_PEER_TIMEOUT       (-6)
#define INDIGO_ERROR_WRONG_PASSWORD     (-7)
#define INDIGO_ERROR_INVALID_PACKET     (-8)
#define INDIGO_ERROR_ACCESS_DENIED      (-9)
#define INDIGO_ERROR_INVALID_PEER_PARAM (-10)
#endif //INDIGO_ERRORS_H
