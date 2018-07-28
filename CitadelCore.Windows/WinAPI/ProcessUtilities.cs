/*
* Copyright © 2017-Present Jesse Nicholson
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

using System;
using System.Runtime.InteropServices;
using System.Text;

namespace CitadelCore.Windows.WinAPI
{
    internal static class ProcessUtilities
    {
        /// <summary>
        /// Attempts to get the symbol path behind a process ID.
        /// </summary>
        /// <param name="processId">
        /// The process ID.
        /// </param>
        /// <returns>
        /// </returns>
        public static string GetProcessName(ulong processId)
        {
            StringBuilder buffer = new StringBuilder(1024);
            IntPtr hprocess = Kernel32.OpenProcess(Kernel32.ProcessAccessFlags.QueryLimitedInformation, false, (uint)processId);
            if (hprocess != IntPtr.Zero)
            {
                try
                {
                    int size = buffer.Capacity;
                    if (Kernel32.QueryFullProcessImageName(hprocess, 0, buffer, ref size))
                    {
                        return buffer.ToString();
                    }
                }
                finally
                {
                    Kernel32.CloseHandle(hprocess);
                }
            }
            return string.Empty;
        }
    }
}