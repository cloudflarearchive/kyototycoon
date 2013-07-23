/*************************************************************************************************
 * Interface for secure connections for Kyoto Tycoon
 *                                                               Copyright (C) 2013 CloudFlare Inc.
 * This file is part of Kyoto Tycoon.
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or any later version.
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 *************************************************************************************************/


#ifndef _KTSOCKETSEC_H                      // duplication check
#define _KTSOCKETSEC_H

#include <ktcommon.h>
#include <ktutil.h>

namespace kyototycoon {                  // common namespace


/**
 * Interface of secure channel connection
 */
class SecChannel {
 public:
  /**
    * enum for state
    */
  enum SecState {
    SSUNSET,
    SSNEGOTIATING,
    SSCTXCREATED,
    SSCREATED,
    SSESTABLISHED
  };
  /**
   * enum for possible errors
   */
  enum SecError {
    SENoError,
    SEFileError,
    SEWantRead,
    SEWantWrite,
    SEInternal,
    SEBadData
  };
  /**
   * Default constructor.
   */
  explicit SecChannel();
  /**
   * Destructor.
   */
  ~SecChannel();
  /**
   * Tear down the one-time resources.
   */
  void teardown();
  /**
   * Get the last happened error information.
   * @return the last happened error information.
   */
  const char* error_msg();
  /**
   * Get the last happened error information.
   * @return the last happened error information.
   */
  SecError error();
  /**
   * Bind a secure client connection over a given connection
   * @return true on success, false on failure
   */
  bool bind_client(int32_t fd, const char* ca, const char* pk, const char* cert);
  /**
   * Bind a secure server connection over a given connection
   * @return true on success, false on failure
   */
  bool bind_server(int32_t fd, const char* ca, const char* pk, const char* cert);
  /**
   * Initiate a secure connection over a given connection
   * @return true on success, false on failure
   */
  bool connect();
  /**
   * Accept a secure connection over a given connection
   * @return true on success, false on failure
   */
  bool accept();
  /**
   * Close the security session.
   * @return true on success, or false on failure.
   */
  bool close();
  /**
   * Send data.
   * @param buf the pointer to a data region to send.
   * @param size the size of the data region.
   * @return size of data sent
   */
  int send(const void* buf, size_t size);
  /**
   * Receive data.
   * @param buf the pointer to the buffer into which the received data is written.
   * @param size the size of the data to receive.
   * @return true on success, or false on failure.
   */
  int receive(void* buf, size_t size);
  /**
   * Retrieve current state
   * @return number of bytes actually received
   */
  SecState secstate();
 private:
  /** Dummy constructor to forbid the use. */
  SecChannel(const SecChannel&);
  /** Dummy Operator to forbid the use. */
  SecChannel& operator =(const SecChannel&);
  /** Opaque pointer. */
  void* opq_;
};


} // common namespace

#endif // duplication check

// END OF FILE
