// Copyright © 2010-2016 The CefSharp Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.

using System;
using System.Collections.Generic;
using System.Linq;
using CefSharp.Internals;
using EasyHook;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace CefSharp.BrowserSubprocess
{
    public class Program
    {
        public static int Main(string[] args)
        {
            InitHook();

            Kernel32.OutputDebugString("BrowserSubprocess starting up with command line: " + String.Join("\n", args));

            CefAppWrapper.EnableHighDPISupport();

            int result;

            using (var subprocess = Create(args))
            {
                result = subprocess.Run();
            }

            Kernel32.OutputDebugString("BrowserSubprocess shutting down.");
            return result;
        }

        private static void InitHook()
        {
            try
            {
                var hook = LocalHook.Create(LocalHook.GetProcAddress("kernel32.dll", "CreateProcessA"), new CreateProcessDelegate(CreateProcessHooked), null);
                hook.ThreadACL.SetExclusiveACL(new int[] { });
                using (var eventLog = new EventLog("Application"))
                {
                    eventLog.Source = "Application";
                    eventLog.WriteEntry("Hook CreateProcess succeed.", EventLogEntryType.Information, 1023, 1);
                }
            }
            catch (Exception e)
            {
                using (var eventLog = new EventLog("Application"))
                {
                    eventLog.Source = "Application";
                    eventLog.WriteEntry("Failed to hook CreateProcess." + Environment.NewLine + e.StackTrace, EventLogEntryType.Warning, 1023, 1);
                }
            }
        }

        public static bool CreateProcessHooked(
            string lpApplicationName,
            string lpCommandLine,
            ref SECURITY_ATTRIBUTES lpProcessAttributes,
            ref SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles,
            UInt32 dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            [In] ref STARTUPINFO lpStartupInfo,
            [In, Out] ref PROCESS_INFORMATION lpProcessInformation)
        {
            if (lpCommandLine.Contains("echo NOT SANDBOXED"))
            {
                return true;
            }
            return CreateProcess(lpApplicationName, lpCommandLine, ref lpProcessAttributes, ref lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, ref lpStartupInfo, ref lpProcessInformation);
        }

        [UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)]
        public delegate bool CreateProcessDelegate(
            string lpApplicationName,
            string lpCommandLine,
            ref SECURITY_ATTRIBUTES lpProcessAttributes,
            ref SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles,
            UInt32 dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            [In] ref STARTUPINFO lpStartupInfo,
            [In, Out] ref PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool CreateProcess(
           string lpApplicationName,
           string lpCommandLine,
           ref SECURITY_ATTRIBUTES lpProcessAttributes,
           ref SECURITY_ATTRIBUTES lpThreadAttributes,
           bool bInheritHandles,
           uint dwCreationFlags,
           IntPtr lpEnvironment,
           string lpCurrentDirectory,
           [In] ref STARTUPINFO lpStartupInfo,
           [In, Out] ref PROCESS_INFORMATION lpProcessInformation);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        private static CefSubProcess Create(IEnumerable<string> args)
        {
            const string typePrefix = "--type=";
            var typeArgument = args.SingleOrDefault(arg => arg.StartsWith(typePrefix));
            var wcfEnabled = args.HasArgument(CefSharpArguments.WcfEnabledArgument);

            var type = typeArgument.Substring(typePrefix.Length);

            switch (type)
            {
                case "renderer":
                    {
                        return wcfEnabled ? new CefRenderProcess(args) : new CefSubProcess(args);
                    }
                case "gpu-process":
                default:
                    {
                        return new CefSubProcess(args);
                    }
            }
        }
    }
}
