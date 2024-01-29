/**
  BSD 3-Clause License

  Copyright (c) 2019, Securifera, Inc. All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  * Redistributions of source code must retain the above copyright notice, this
    list of conditions and the following disclaimer.

  * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

  * Neither the name of the copyright holder nor the names of its
    contributors may be used to endorse or promote products derived from
    this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <windows.h>
#include <stdio.h>
#include <lm.h>
#include "net_share.h"
#include "debug.h"
#include "utils.h"

#pragma comment(lib, "Netapi32.lib")
#pragma comment(lib, "Advapi32.lib")

void net_view( std::string srv_str )
{
    PSHARE_INFO_1 BufPtr, p;
    NET_API_STATUS res;
    BOOL ret_val;
    DWORD er = 0, tr = 0, resume = 0, i;
    std::wstring srv_wide(srv_str.begin(), srv_str.end());
 
    // Attempt the enumerate the network shares of the remote server
    res = NetShareEnum((LPWSTR)srv_wide.c_str(), 1, (LPBYTE*)&BufPtr, MAX_PREFERRED_LENGTH, &er, &tr, &resume);
    if (res == ERROR_SUCCESS || res == ERROR_MORE_DATA)
    {
        // Print a report header.
        DebugFprintf(outlogfile, PRINT_INFO1, "\n\tShare:                Type:     Remarks:            Access:\n");
        DebugFprintf(outlogfile, PRINT_INFO1, "\t-------------------------------------------------------------\n");

        do {

            p = BufPtr;
            for (i = 1; i <= er; i++)
            {
                DWORD disk_type = 0xff & p->shi1_type;
                std::string access("");

                if (disk_type == STYPE_DISKTREE) {

                    //List files
                    std::wstring wshare_name(p->shi1_netname);
                    std::string remote_path("\\\\");
                    remote_path.append(srv_str);
                    remote_path.append("\\");
                    remote_path.append(ws2s(wshare_name));
                    //remote_path.append(share_name.begin(), share_name.end());

                    std::vector<FileInfo*> file_list;
                    ret_val = list_files(remote_path, &file_list);
                    if (ret_val)
                        access.append("READ-ACCESS ");

                    //Free memory
                    for (std::vector<FileInfo*>::iterator files_it = file_list.begin();
                        files_it != file_list.end(); ++files_it) {

                        FileInfo *file_info = *files_it;
                        delete(file_info);                        
                    }

                    ret_val = check_write_access(remote_path);
                    if (ret_val)
                        access.append("WRITE-ACCESS ");
                    
                }

                DebugFprintf(outlogfile, PRINT_INFO1, "\t%-22S%-10d%-20S%-20s\n", p->shi1_netname, 0xff & p->shi1_type, p->shi1_remark, access.c_str());
                p++;
            }

            // Free the allocated buffer.
            NetApiBufferFree(BufPtr);
            BufPtr = 0;
            

            //Get next share info
            if(res == ERROR_MORE_DATA)
                res = NetShareEnum((LPWSTR)srv_wide.c_str(), 1, (LPBYTE*)&BufPtr, MAX_PREFERRED_LENGTH, &er, &tr, &resume);

        } while (res == ERROR_MORE_DATA);
        
    }
    else {
        DebugFprintf(outlogfile, PRINT_INFO1, "\t[-] Unable to enumerate shares. Error: %ld\n", res);
    }

    return;
}