﻿/*
MIT License

Copyright (c) 2019 Digital Ruby, LLC - https://www.digitalruby.com

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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Text;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Utility methods for working with firewall data
    /// </summary>
    public static class IPBanFirewallUtility
    {
        private static readonly char[] ipV4Delimiters = new char[] { '-', ':', '/' };
        private static void AppendRange(StringBuilder b, PortRange range)
        {
            string rangeString = range.ToString();
            if (rangeString != null)
            {
                b.Append(range);
                b.Append(',');
            }
        }

        /// <summary>
        /// Get a firewall ip address, clean and normalize
        /// </summary>
        /// <param name="ipAddress">IP Address</param>
        /// <param name="normalizedIP">The normalized ip ready to go in the firewall or null if invalid ip address</param>
        /// <returns>True if ip address can go in the firewall, false otherwise</returns>
        public static bool TryNormalizeIPAddress(this string ipAddress, out string normalizedIP)
        {
            normalizedIP = (ipAddress ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(normalizedIP) ||
                normalizedIP == "-" ||
                normalizedIP == "0.0.0.0" ||
                normalizedIP == "127.0.0.1" ||
                normalizedIP == "::0" ||
                normalizedIP == "::1" ||
                !IPAddressRange.TryParse(normalizedIP, out IPAddressRange range))
            {
                // try parsing assuming the ip is followed by a port
                int pos = normalizedIP.LastIndexOf(':');
                if (pos >= 0)
                {
                    normalizedIP = normalizedIP.Substring(0, pos);
                    if (!IPAddressRange.TryParse(normalizedIP, out range))
                    {
                        normalizedIP = null;
                        return false;
                    }
                }
                else
                {
                    normalizedIP = null;
                    return false;
                }
            }
            try
            {
                normalizedIP = (range.Begin.Equals(range.End) ? range.Begin.ToString() : range.ToCidrString());
            }
            catch (Exception ex)
            {
                Logger.Debug("Failed to normalize ip {0}, it is not a single ip or cidr range: {1}", ipAddress, ex);
                return false;
            }
            return true;
        }

        /// <summary>
        /// Create a firewall
        /// </summary>
        /// <param name="osAndFirewall">Dictionary of string operating system name (Windows, Linux, OSX) and firewall class</param>
        /// <param name="rulePrefix">Rule prefix or null for default</param>
        /// <returns>Firewall</returns>
        public static IIPBanFirewall CreateFirewall(IReadOnlyDictionary<string, string> osAndFirewall, string rulePrefix = null, IIPBanFirewall existing = null)
        {
            try
            {
                bool foundFirewallType = false;
                int priority = int.MinValue;
                Type firewallType = typeof(IIPBanFirewall);
                List<Type> allTypes = ExtensionMethods.GetAllTypes();
                var q =
                    from fwType in allTypes
                    where fwType.IsPublic &&
                        fwType != firewallType &&
                        firewallType.IsAssignableFrom(fwType) &&
                        fwType.GetCustomAttribute<RequiredOperatingSystemAttribute>() != null &&
                        fwType.GetCustomAttribute<RequiredOperatingSystemAttribute>().IsValid
                    select new { FirewallType = fwType, OS = fwType.GetCustomAttribute<RequiredOperatingSystemAttribute>(), Name = fwType.GetCustomAttribute<CustomNameAttribute>() };
                var array = q.ToArray();
                foreach (var result in array)
                {
                    // look up the requested firewall by os name
                    bool matchPriority = priority < result.OS.Priority;
                    if (matchPriority)
                    {
                        bool matchName = true;
                        if (osAndFirewall != null && osAndFirewall.Count != 0 &&
                            (osAndFirewall.TryGetValue(OSUtility.Name, out string firewallToUse) || osAndFirewall.TryGetValue("*", out firewallToUse)))
                        {
                            matchName = result.Name.Name.Equals(firewallToUse, StringComparison.OrdinalIgnoreCase);
                        }
                        if (matchName)
                        {
                            // if IsAvailable method is provided, attempt to call
                            MethodInfo available = result.FirewallType.GetMethod("IsAvailable", BindingFlags.Public | BindingFlags.Static | BindingFlags.FlattenHierarchy);
                            if (available != null)
                            {
                                try
                                {
                                    if (!Convert.ToBoolean(available.Invoke(null, null)))
                                    {
                                        continue;
                                    }
                                }
                                catch
                                {
                                    continue;
                                }
                            }
                            firewallType = result.FirewallType;
                            priority = result.OS.Priority;
                            foundFirewallType = true;
                        }
                    }
                }
                if (firewallType is null)
                {
                    throw new ArgumentException("Firewall is null, at least one type should implement IIPBanFirewall");
                }
                else if (osAndFirewall.Count != 0 && !foundFirewallType)
                {
                    string typeString = string.Join(',', osAndFirewall.Select(kv => kv.Key + ":" + kv.Value));
                    throw new ArgumentException("Unable to find firewalls of types: " + typeString + ", osname: " + OSUtility.Name);
                }
                if (existing != null && existing.GetType().Equals(firewallType))
                {
                    return existing;
                }
                return Activator.CreateInstance(firewallType, new object[] { rulePrefix }) as IIPBanFirewall;
            }
            catch (Exception ex)
            {
                throw new ArgumentException("Unable to create firewall, please double check your Firewall configuration property", ex);
            }
        }

        /// <summary>
        /// Compare two ip address for sort order
        /// </summary>
        /// <param name="ip1">First ip address</param>
        /// <param name="ip2">Second ip address</param>
        /// <returns>CompareTo result (negative less than, 0 equal, 1 greater than)</returns>
        public static int CompareTo(this IPAddress ip1, IPAddress ip2)
        {
            if (ip1 is null)
            {
                return (ip2 is null ? 0 : -1);
            }

            byte[] bytes1 = ip1.GetAddressBytes();
            byte[] bytes2 = ip2.GetAddressBytes();
            if (bytes1.Length != bytes2.Length)
            {
                return (bytes1.Length > bytes2.Length ? 1 : -1);
            }
            for (int byteIndex = 0; byteIndex < bytes1.Length; byteIndex++)
            {
                int result = bytes1[byteIndex].CompareTo(bytes2[byteIndex]);
                if (result != 0)
                {
                    return result;
                }
            }
            return 0;
        }

        /// <summary>
        /// Increment an ip address
        /// </summary>
        /// <param name="ipAddress">Ip address to increment</param>
        /// <param name="result">Incremented ip address or null if failure</param>
        /// <returns>True if incremented, false if ip address was at max value</returns>
        public static bool TryIncrement(this IPAddress ipAddress, out IPAddress result)
        {
            byte[] bytes = ipAddress.GetAddressBytes();

            for (int k = bytes.Length - 1; k >= 0; k--)
            {
                if (bytes[k] == byte.MaxValue)
                {
                    bytes[k] = 0;
                    continue;
                }

                bytes[k]++;

                result = new IPAddress(bytes);
                return true;
            }

            // all bytes are already max values, no increment possible
            result = null;
            return false;
        }

        /// <summary>
        /// Decrement an ip address
        /// </summary>
        /// <param name="ipAddress">Ip address to decrement</param>
        /// <param name="result">Decremented ip address or null if failure</param>
        /// <returns>True if decremented, false if ip address was at min value</returns>
        public static bool TryDecrement(this IPAddress ipAddress, out IPAddress result)
        {
            byte[] bytes = ipAddress.GetAddressBytes();

            for (int k = bytes.Length - 1; k >= 0; k--)
            {
                if (bytes[k] == 0)
                {
                    bytes[k] = byte.MaxValue;
                    continue;
                }

                bytes[k]--;
                result = new IPAddress(bytes);
                return true;
            }

            // all bytes are already min values, no decrement possible
            result = null;
            return false;
        }

        /// <summary>
        /// Get a port range of block ports except the passed in port ranges
        /// </summary>
        /// <param name="portRanges">Port ranges to allow, all other ports are blocked</param>
        /// <returns>Port range string to block (i.e. 0-79,81-442,444-65535)</returns>
        public static string GetPortRangeStringBlockExcept(IEnumerable<PortRange> portRanges)
        {
            if (portRanges is null)
            {
                return null;
            }
            StringBuilder b = new StringBuilder();
            int currentPort = 0;
            foreach (PortRange range in portRanges.Where(r => r.IsValid).OrderBy(r => r.MinPort))
            {
                // if current port less than min, append range
                if (currentPort < range.MinPort)
                {
                    int maxPort = range.MinPort - 1;
                    AppendRange(b, new PortRange(currentPort, maxPort));
                    currentPort = range.MaxPort + 1;
                }
                // if current port in range, append the overlapped range
                else if (currentPort >= range.MinPort && currentPort <= range.MaxPort)
                {
                    AppendRange(b, new PortRange(range.MinPort, currentPort));
                    currentPort++;
                }
                // append the after range to current port
                else if (currentPort <= range.MaxPort)
                {
                    AppendRange(b, new PortRange(range.MaxPort + 1, currentPort));
                    currentPort++;
                }
            }
            if (currentPort != 0)
            {
                AppendRange(b, new PortRange(currentPort, 65535));
            }

            // trim ending comma
            if (b.Length != 0)
            {
                b.Length--;
            }
            return (b.Length == 0 ? null : b.ToString());
        }

        /// <summary>
        /// Get a port range of allow ports. Overlaps are thrown out.
        /// </summary>
        /// <param name="portRanges">Port ranges to allow</param>
        /// <returns>Port range string to allow (i.e. 80,443,1000-10010)</returns>
        public static string GetPortRangeStringAllow(IEnumerable<PortRange> portRanges)
        {
            StringBuilder b = new StringBuilder();
            if (portRanges != null)
            {
                int lastMax = -1;
                foreach (PortRange range in portRanges.OrderBy(p => p.MinPort))
                {
                    if (range.MinPort > lastMax)
                    {
                        AppendRange(b, range);
                        lastMax = range.MaxPort;
                    }
                }
            }

            // trim end comma
            if (b.Length != 0)
            {
                b.Length--;
            }
            return (b.Length == 0 ? null : b.ToString());
        }

        /// <summary>
        /// Filter ip address ranges from ranges using filter
        /// </summary>
        /// <param name="ranges">Ip address ranges to filter</param>
        /// <param name="filter">Ip address ranges to filter out of ranges, null for no filtering</param>
        /// <returns>Filtered ip address ranges in sorted order</returns>
        public static IEnumerable<IPAddressRange> FilterRanges(this IEnumerable<IPAddressRange> ranges, IEnumerable<IPAddressRange> filter)
        {
            // if null ranges we are done
            if (ranges is null)
            {
                yield break;
            }

            // if null filter, return ranges as is
            else if (filter is null)
            {
                foreach (IPAddressRange range in ranges.OrderBy(r => r))
                {
                    yield return range;
                }
                yield break;
            }

            using (IEnumerator<IPAddressRange> rangeEnum = ranges.OrderBy(r => r).GetEnumerator())
            using (IEnumerator<IPAddressRange> filterEnum = filter.OrderBy(r => r).GetEnumerator())
            {
                // if no ranges left, we are done
                if (!rangeEnum.MoveNext())
                {
                    yield break;
                }

                IPAddressRange currentFilter = (filterEnum.MoveNext() ? filterEnum.Current : null);
                IPAddressRange currentRange = rangeEnum.Current;
                while (true)
                {
                    // if no more filter, just continue returning ranges as is
                    if (currentFilter is null)
                    {
                        yield return currentRange;
                        if (!rangeEnum.MoveNext())
                        {
                            break;
                        }
                        continue;
                    }

                    int compare = currentFilter.Begin.CompareTo(currentRange.End);
                    if (compare > 0)
                    {
                        // current filter begin is after the range end, just return the range as is
                        yield return currentRange;
                        if (!rangeEnum.MoveNext())
                        {
                            break;
                        }
                        currentRange = rangeEnum.Current;
                    }
                    else
                    {
                        compare = currentFilter.End.CompareTo(currentRange.Begin);

                        // check if the current filter end is before the range begin
                        if (compare < 0)
                        {
                            // current filter end is before the range begin, move to next filter
                            currentFilter = (filterEnum.MoveNext() ? filterEnum.Current : null);
                        }
                        else
                        {
                            // the current filter is inside the current range, filter
                            int compareBegin = currentFilter.Begin.CompareTo(currentRange.Begin);
                            int compareEnd = currentFilter.End.CompareTo(currentRange.End);
                            if (compareBegin <= 0)
                            {
                                // filter begin is less than or equal to the range begin
                                if (compareEnd < 0 && currentFilter.End.TryIncrement(out IPAddress begin))
                                {
                                    // set the range to have the filtered portion removed
                                    currentRange = new IPAddressRange(begin, currentRange.End);

                                    // move to next filter
                                    currentFilter = (filterEnum.MoveNext() ? filterEnum.Current : currentFilter);
                                }
                                else
                                {
                                    // else the filter has blocked out this entire range, ignore it
                                    if (!rangeEnum.MoveNext())
                                    {
                                        break;
                                    }
                                    currentRange = rangeEnum.Current;
                                }
                            }
                            else
                            {
                                // if compareBegin was >= the ip address range begin, we won't get here
                                // this means the current filter begin must be greater than 0
                                if (!currentFilter.Begin.TryDecrement(out IPAddress end))
                                {
                                    throw new InvalidOperationException("Current filter should have been able to decrement the begin ip address");
                                }

                                // filter begin is after the range begin, return the range begin and one before the filter begin
                                yield return new IPAddressRange(currentRange.Begin, end);
                                if (!currentFilter.End.TryIncrement(out IPAddress newBegin))
                                {
                                    newBegin = currentFilter.End;
                                }

                                if (newBegin.CompareTo(currentRange.End) > 0)
                                {
                                    // end of range, get a new range
                                    if (!rangeEnum.MoveNext())
                                    {
                                        break;
                                    }
                                    currentRange = rangeEnum.Current;
                                }
                                else
                                {
                                    currentRange = new IPAddressRange(newBegin, currentRange.End);
                                }
                            }
                        }
                    }
                }
            }
        }


    }
}
