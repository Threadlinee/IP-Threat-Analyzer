using System;
using System.IO;
using System.Net;
using Newtonsoft.Json.Linq;

namespace IPGeolocationThreatScanner
{
    class Program
    {
        static string apiKey = "96fd8f01f0cf4d3b86da7aa9ad9200d8";

        static void Main(string[] args)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(@"
/* @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ */
/* @                                                                              @ */
/* @   ▪   ▄▄▄·     ▄▄ • ▄▄▄ .      ▄▄▌         ▄▄·  ▄▄▄· ▄▄▄▄▄▪         ▐ ▄      @ */
/* @   ██ ▐█ ▄█    ▐█ ▀ ▪▀▄.▀·▪     ██•  ▪     ▐█ ▌▪▐█ ▀█ •██  ██ ▪     •█▌▐█     @ */
/* @   ▐█· ██▀·    ▄█ ▀█▄▐▀▀▪▄ ▄█▀▄ ██▪   ▄█▀▄ ██ ▄▄▄█▀▀█  ▐█.▪▐█· ▄█▀▄ ▐█▐▐▌     @ */
/* @   ▐█▌▐█▪·•    ▐█▄▪▐█▐█▄▄▌▐█▌.▐▌▐█▌▐▌▐█▌.▐▌▐███▌▐█ ▪▐▌ ▐█▌·▐█▌▐█▌.▐▌██▐█▌     @ */
/* @   ▀▀▀.▀       ·▀▀▀▀  ▀▀▀  ▀█▄▀▪.▀▀▀  ▀█▄▀▪·▀▀▀  ▀  ▀  ▀▀▀ ▀▀▀ ▀█▄▀▪▀▀ █▪     @ */
/* @   ▄▄▄▄▄ ▄ .▄▄▄▄  ▄▄▄ . ▄▄▄· ▄▄▄▄▄    .▄▄ ·  ▄▄·  ▄▄▄·  ▐ ▄  ▐ ▄ ▄▄▄ .▄▄▄     @ */
/* @   •██  ██▪▐█▀▄ █·▀▄.▀·▐█ ▀█ •██      ▐█ ▀. ▐█ ▌▪▐█ ▀█ •█▌▐█•█▌▐█▀▄.▀·▀▄ █·   @ */
/* @    ▐█.▪██▀▐█▐▀▀▄ ▐▀▀▪▄▄█▀▀█  ▐█.▪    ▄▀▀▀█▄██ ▄▄▄█▀▀█ ▐█▐▐▌▐█▐▐▌▐▀▀▪▄▐▀▀▄    @ */
/* @    ▐█▌·██▌▐▀▐█•█▌▐█▄▄▌▐█ ▪▐▌ ▐█▌·    ▐█▄▪▐█▐███▌▐█ ▪▐▌██▐█▌██▐█▌▐█▄▄▌▐█•█▌   @ */
/* @    ▀▀▀ ▀▀▀ ·.▀  ▀ ▀▀▀  ▀  ▀  ▀▀▀      ▀▀▀▀ ·▀▀▀  ▀  ▀ ▀▀ █▪▀▀ █▪ ▀▀▀ .▀  ▀   @ */
/* @                                                                              @ */
/* @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ */
");
            Console.ResetColor();

            bool running = true;

            while (running)
            {
                Console.WriteLine("\nChoose an option:");
                Console.WriteLine("1) Track your own IP Address");
                Console.WriteLine("2) Scan an IP Address");
                Console.WriteLine("3) Exit");

                string option = Console.ReadLine();

                switch (option)
                {
                    case "1":
                        TrackOwnIP();
                        break;
                    case "2":
                        Console.Write("Enter the IP Address to scan: ");
                        string ipAddress = Console.ReadLine();
                        ScanIP(ipAddress);
                        break;
                    case "3":
                        Console.WriteLine("\nExiting the program...");
                        running = false;
                        break;
                    default:
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("\n[!] Invalid option, please try again.");
                        Console.ResetColor();
                        break;
                }
            }
        }

        static void TrackOwnIP()
        {
            try
            {
                string ipData = new WebClient().DownloadString($"https://api.ipgeolocation.io/ipgeo?apiKey={apiKey}");
                JObject ipJson = JObject.Parse(ipData);

                string ip = ipJson["ip"]?.ToString();
                string city = ipJson["city"]?.ToString();
                string state = ipJson["state_prov"]?.ToString();
                string country = ipJson["country_name"]?.ToString();
                string isp = ipJson["isp"]?.ToString();
                string latitude = ipJson["latitude"]?.ToString();
                string longitude = ipJson["longitude"]?.ToString();
                string timezone = ipJson["time_zone"]["name"]?.ToString();
                string currency = ipJson["currency"]["name"]?.ToString();

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"[+] IP Address   : {ip}");
                Console.WriteLine($"[+] Location     : {city}, {state}, {country}");
                Console.WriteLine($"[+] Latitude     : {latitude}");
                Console.WriteLine($"[+] Longitude    : {longitude}");
                Console.WriteLine($"[+] ISP          : {isp}");
                Console.WriteLine($"[+] Timezone     : {timezone}");
                Console.WriteLine($"[+] Currency     : {currency}");
                Console.ResetColor();

                string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "ip_info.txt");
                File.WriteAllText(path,
                    $"IP: {ip}\nLocation: {city}, {state}, {country}\nLatitude: {latitude}\nLongitude: {longitude}\nISP: {isp}\nTimezone: {timezone}\nCurrency: {currency}");

                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine($"\n[✓] Geo data saved to: {path}\n");
                Console.ResetColor();

                GetThreatInfo(ip);

                Console.WriteLine("\nPress any key to return to the main menu...");
                Console.ReadKey();  // Wait for the user to press a key
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\n[X] Failed to fetch geo data.");
                Console.WriteLine("Error: " + ex.Message);
                Console.ResetColor();
            }
        }

        static void ScanIP(string ipAddress)
        {
            Console.WriteLine($"\n[+] Scanning IP: {ipAddress} ...");

            try
            {
                string ipData = new WebClient().DownloadString($"https://api.ipgeolocation.io/ipgeo?apiKey={apiKey}&ip={ipAddress}");
                JObject ipJson = JObject.Parse(ipData);

                string ip = ipJson["ip"]?.ToString();
                string city = ipJson["city"]?.ToString();
                string state = ipJson["state_prov"]?.ToString();
                string country = ipJson["country_name"]?.ToString();
                string isp = ipJson["isp"]?.ToString();
                string latitude = ipJson["latitude"]?.ToString();
                string longitude = ipJson["longitude"]?.ToString();
                string timezone = ipJson["time_zone"]["name"]?.ToString();
                string currency = ipJson["currency"]["name"]?.ToString();

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"[+] IP Address   : {ip}");
                Console.WriteLine($"[+] Location     : {city}, {state}, {country}");
                Console.WriteLine($"[+] Latitude     : {latitude}");
                Console.WriteLine($"[+] Longitude    : {longitude}");
                Console.WriteLine($"[+] ISP          : {isp}");
                Console.WriteLine($"[+] Timezone     : {timezone}");
                Console.WriteLine($"[+] Currency     : {currency}");
                Console.ResetColor();

                string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "ip_info.txt");
                File.WriteAllText(path,
                    $"IP: {ip}\nLocation: {city}, {state}, {country}\nLatitude: {latitude}\nLongitude: {longitude}\nISP: {isp}\nTimezone: {timezone}\nCurrency: {currency}");

                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine($"\n[✓] Geo data saved to: {path}\n");
                Console.ResetColor();

                GetThreatInfo(ipAddress);

                Console.WriteLine("\nPress any key to return to the main menu...");
                Console.ReadKey();  // Wait for the user to press a key
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\n[X] Failed to fetch geo data.");
                Console.WriteLine("Error: " + ex.Message);
                Console.ResetColor();
            }
        }

        static void GetThreatInfo(string ip)
        {
            try
            {
                // Using ip-api's free VPN detection
                string threatData = new WebClient().DownloadString($"http://ip-api.com/json/{ip}?fields=proxy,host,isp,query,tor,bot");
                JObject threatJson = JObject.Parse(threatData);

                bool isVPN = threatJson["proxy"]?.ToString() == "yes";
                string isp = threatJson["isp"]?.ToString();
                bool isTor = threatJson["tor"]?.ToString() == "yes";
                bool isBot = threatJson["bot"]?.ToString() == "yes";

                // Show VPN Status, ISP, and others
                Console.WriteLine($"[?] VPN: {(isVPN ? "Detected" : "Not Detected")}");
                Console.WriteLine($"[?] ISP: {isp}");
                Console.WriteLine($"[?] TOR: {(isTor ? "Detected" : "Not Detected")}");
                Console.WriteLine($"[?] Bot Status: {(isBot ? "Detected" : "Clean")}");
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\n[X] Failed to detect VPN, TOR, or Bot.");
                Console.WriteLine("Error: " + ex.Message);
                Console.ResetColor();
            }
        }
    }
}
