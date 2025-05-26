using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using System.ServiceProcess;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using System.Collections.Generic;
using System.Linq;
using System.ComponentModel;
using System.Configuration.Install;
using System.Security.Principal;

namespace NovaEDR.Agent
{

    // Hard-coded server URL that cannot be changed by clients
    public static class Constants
    {
        public const string SERVER_URL = "https://raw.githubusercontent.com/N0vaSky/NovaEDR-deploy/";
        public const int DEFAULT_UPDATE_INTERVAL_MINUTES = 60; // Set to 60 minutes
        public const string DEFAULT_CLIENT_ID = "nhpdriXRA3M9Fs7rKkaAtG2lI"; // Default branch/client ID
    }

    public class NovaEDR
    {
        public static void Main(string[] args)
        {
            // Add basic console output for debugging
            Console.WriteLine($"Nova EDR Agent starting with args: {string.Join(", ", args)}");

            try
            {
                if (args.Length > 0)
                {
                    switch (args[0].ToLower())
                    {
                        case "--console":
                            // Run in console mode for debugging
                            var agent = new NovaEDRAgent();
                            agent.StartConsole(args);
                            Console.WriteLine("Press any key to exit...");
                            Console.ReadKey();
                            break;

                        case "--install":
                            // Install the service
                            InstallService();
                            break;

                        case "--uninstall":
                            // Uninstall the service and components
                            UninstallService();
                            break;

                        case "--version":
                            // Display version info
                            Console.WriteLine($"Nova EDR Agent v{Assembly.GetExecutingAssembly().GetName().Version}");
                            break;

                        default:
                            ShowHelp();
                            break;
                    }
                }
                else
                {
                    // Run as Windows service
                    ServiceBase.Run(new ServiceBase[] { new NovaEDRAgent() });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Critical error: {ex.Message}");
                Console.WriteLine(ex.StackTrace);
                File.WriteAllText("NovaEDRError.log", $"{DateTime.Now}: {ex.Message}\n{ex.StackTrace}");
                Console.WriteLine("Press any key to exit...");
                Console.ReadKey();
            }
        }

        private static void ShowHelp()
        {
            Console.WriteLine("Nova EDR Agent - Unified EDR Solution Agent");
            Console.WriteLine("Usage:");
            Console.WriteLine("  NovaEDRAgent.exe                  - Run as a service (normal operation)");
            Console.WriteLine("  NovaEDRAgent.exe --console        - Run in console mode for testing");
            Console.WriteLine("  NovaEDRAgent.exe --install        - Install the service");
            Console.WriteLine("  NovaEDRAgent.exe --uninstall      - Uninstall the service and components");
            Console.WriteLine("  NovaEDRAgent.exe --version        - Display version information");
        }

        private static void InstallService()
        {
            try
            {
                // Parse command line arguments - only looking for CLIENT_ID now
                string clientId = null;
                string wazuhGroups = null;

                // Get command line arguments from Environment
                string[] args = Environment.GetCommandLineArgs();
                for (int i = 0; i < args.Length; i++)
                {
                    string arg = args[i];

                    // Look for CLIENT_ID parameter
                    if (arg.StartsWith("CLIENT_ID=", StringComparison.OrdinalIgnoreCase))
                    {
                        clientId = arg.Substring("CLIENT_ID=".Length).Trim('"');
                        Console.WriteLine($"Found CLIENT_ID: {clientId}");
                    }

                    // Look for WAZUH_GROUPS parameter
                    else if (arg.StartsWith("WAZUH_GROUPS=", StringComparison.OrdinalIgnoreCase))
                    {
                        wazuhGroups = arg.Substring("WAZUH_GROUPS=".Length).Trim('"');
                        Console.WriteLine($"Found WAZUH_GROUPS: {wazuhGroups}");
                    }
                }

                // If no client ID specified, prompt for it
                if (string.IsNullOrEmpty(clientId))
                {
                    Console.WriteLine($"No CLIENT_ID specified. Please enter the client ID (default: {Constants.DEFAULT_CLIENT_ID}):");
                    clientId = Console.ReadLine()?.Trim();

                    if (string.IsNullOrEmpty(clientId))
                    {
                        clientId = Constants.DEFAULT_CLIENT_ID;
                        Console.WriteLine($"Using default CLIENT_ID: {clientId}");
                    }
                }

                Console.WriteLine($"Installing service with SERVER_URL={Constants.SERVER_URL}, CLIENT_ID={clientId}");

                // Create required directories
                CreateProgramDataDirectories();

                // Create initial config file 
                string configPath = @"C:\ProgramData\NovaEDR\Config";
                string configFilePath = Path.Combine(configPath, "config.json");

                // Create configuration object with hardcoded server URL
                var config = new Dictionary<string, object>
            {
                { "ServerUrl", Constants.SERVER_URL },
                { "ClientId", clientId ?? "default" },
                { "UpdateIntervalMinutes", Constants.DEFAULT_UPDATE_INTERVAL_MINUTES },
                { "LogLevel", "Info" },
                { "LogPath", @"C:\ProgramData\NovaEDR\Logs" },
                { "ConfigPath", configPath },
                { "TempPath", @"C:\ProgramData\NovaEDR\Temp" }
            };

                // Add Wazuh Groups if specified
                if (!string.IsNullOrEmpty(wazuhGroups))
                {
                    config["WazuhGroups"] = wazuhGroups;
                }

                // Save configuration to file
                File.WriteAllText(configFilePath, JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true }));
                Console.WriteLine($"Created configuration file at {configFilePath}");

                // Now install the service
                Console.WriteLine("Installing service...");
                ManagedInstallerClass.InstallHelper(new string[] { Assembly.GetExecutingAssembly().Location });
                Console.WriteLine("Nova EDR Agent service installed successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error installing service: {ex.Message}");
                File.WriteAllText("InstallError.log", $"{DateTime.Now}: {ex.Message}\n{ex.StackTrace}");
            }
        }

        private static void CreateProgramDataDirectories()
        {
            string logPath = @"C:\ProgramData\NovaEDR\Logs";
            string configPath = @"C:\ProgramData\NovaEDR\Config";
            string tempPath = @"C:\ProgramData\NovaEDR\Temp";

            if (!Directory.Exists(logPath)) Directory.CreateDirectory(logPath);
            if (!Directory.Exists(configPath)) Directory.CreateDirectory(configPath);
            if (!Directory.Exists(tempPath)) Directory.CreateDirectory(tempPath);

            Console.WriteLine("Created required directories");
        }

        private static void StartProcess(string fileName, string arguments)
        {
            try
            {
                ProcessStartInfo startInfo = new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = arguments,
                    UseShellExecute = true,
                    Verb = "runas",
                    WindowStyle = ProcessWindowStyle.Normal // Make visible for debugging
                };

                Process process = Process.Start(startInfo);
                process.WaitForExit();
                Console.WriteLine($"Process {fileName} exited with code: {process.ExitCode}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error executing process {fileName}: {ex.Message}");
            }
        }

        private static void UninstallService()
        {
            try
            {
                // First uninstall all components using the improved method
                Console.WriteLine("Uninstalling components...");

                // Use PowerShell-based uninstallation instead of WMIC
                UninstallProductWithPowerShell("Fibratus");
                UninstallProductWithPowerShell("Velociraptor");
                UninstallProductWithPowerShell("Wazuh");
                UninstallProductWithPowerShell("Nova EDR");

                // Now uninstall the service
                Console.WriteLine("Uninstalling Nova EDR Agent service...");
                ManagedInstallerClass.InstallHelper(new string[] { "/u", Assembly.GetExecutingAssembly().Location });
                Console.WriteLine("Nova EDR Agent service uninstalled successfully.");

                // Clean up configuration and logs
                try
                {
                    string configDir = @"C:\ProgramData\NovaEDR";
                    if (Directory.Exists(configDir))
                    {
                        Directory.Delete(configDir, true);
                        Console.WriteLine("Removed Nova EDR configuration directory");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error removing Nova EDR configuration: {ex.Message}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error uninstalling service: {ex.Message}");
                File.WriteAllText("UninstallError.log", $"{DateTime.Now}: {ex.Message}\n{ex.StackTrace}");
            }
        }

        private static void UninstallProductWithPowerShell(string productName)
        {
            try
            {
                Console.WriteLine($"Uninstalling {productName} using PowerShell...");

                // Create PowerShell script to find and uninstall products
                string script = $@"
            $products = Get-WmiObject -Class Win32_Product | Where-Object {{
                $_.Name -like '*{productName}*' -or 
                $_.DisplayName -like '*{productName}*' -or
                $_.Description -like '*{productName}*'
            }}
            
            foreach ($product in $products) {{
                Write-Host ""Found product: $($product.Name) - $($product.IdentifyingNumber)""
                try {{
                    $result = $product.Uninstall()
                    if ($result.ReturnValue -eq 0) {{
                        Write-Host ""Successfully uninstalled: $($product.Name)""
                    }} else {{
                        Write-Host ""Uninstall failed with return code: $($result.ReturnValue)""
                    }}
                }} catch {{
                    Write-Host ""Error uninstalling $($product.Name): $($_.Exception.Message)""
                }}
            }}
        ";

                // Execute PowerShell script
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "powershell.exe",
                        Arguments = $"-Command \"{script}\"",
                        UseShellExecute = true,
                        Verb = "runas",
                        WindowStyle = ProcessWindowStyle.Normal,
                        CreateNoWindow = false
                    }
                };

                process.Start();
                process.WaitForExit();

                Console.WriteLine($"PowerShell uninstall for {productName} completed with exit code: {process.ExitCode}");

                // Verify removal and clean up manually if needed
                CleanupAfterUninstall(productName);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error uninstalling {productName} with PowerShell: {ex.Message}");
                // Fallback to manual cleanup
                CleanupAfterUninstall(productName);
            }
        }

        private static void CleanupAfterUninstall(string productName)
        {
            try
            {
                // Stop and remove any remaining services
                var services = FindServicesByProduct(productName);
                foreach (var serviceName in services)
                {
                    StopAndRemoveService(serviceName);
                }

                // Remove directories
                var directories = GetProductDirectories(productName);
                foreach (var directory in directories)
                {
                    DeleteDirectory(directory);
                }

                Console.WriteLine($"Manual cleanup completed for {productName}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error during manual cleanup for {productName}: {ex.Message}");
            }
        }

        private static List<string> FindServicesByProduct(string productName)
        {
            var services = new List<string>();

            try
            {
                // Search by executable path using PowerShell
                string script = $@"
            Get-WmiObject -Class Win32_Service | Where-Object {{
                $_.Name -like '*{productName}*' -or 
                $_.DisplayName -like '*{productName}*' -or
                $_.PathName -like '*{productName}*'
            }} | ForEach-Object {{ $_.Name }}
        ";

                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "powershell.exe",
                        Arguments = $"-Command \"{script}\"",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                if (!string.IsNullOrEmpty(output))
                {
                    var foundServices = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                    services.AddRange(foundServices.Select(s => s.Trim()).Where(s => !string.IsNullOrEmpty(s)));
                }

                // Add known patterns as fallback
                var patterns = GetServiceNamePatterns(productName);
                services.AddRange(patterns.Where(ServiceExists));

                Console.WriteLine($"Found {services.Count} services for {productName}: {string.Join(", ", services)}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error finding services for {productName}: {ex.Message}");
                // Fallback to hardcoded patterns
                services.AddRange(GetServiceNamePatterns(productName).Where(ServiceExists));
            }

            return services.Distinct().ToList();
        }

        private static List<string> GetServiceNamePatterns(string productName)
        {
            var patterns = new List<string>();

            switch (productName.ToLower())
            {
                case "fibratus":
                    patterns.AddRange(new[] { "Fibratus", "fibratus" });
                    break;
                case "velociraptor":
                case "nova edr":
                    patterns.AddRange(new[] { "Velociraptor", "velociraptor", "VelociraptorService" });
                    break;
                case "wazuh":
                    patterns.AddRange(new[] { "Wazuh", "wazuh-agent", "WazuhSvc", "wazuh_agent", "WazuhAgent" });
                    break;
            }

            return patterns;
        }

        private static List<string> GetProductDirectories(string productName)
        {
            var directories = new List<string>();

            switch (productName.ToLower())
            {
                case "fibratus":
                    directories.AddRange(new[]
                    {
                @"C:\Program Files\Fibratus",
                @"C:\Program Files (x86)\Fibratus"
            });
                    break;
                case "velociraptor":
                case "nova edr":
                    directories.AddRange(new[]
                    {
                @"C:\Program Files\Velociraptor",
                @"C:\Program Files (x86)\Velociraptor"
            });
                    break;
                case "wazuh":
                    directories.AddRange(new[]
                    {
                @"C:\Program Files\Wazuh",
                @"C:\Program Files\Wazuh Agent",
                @"C:\Program Files (x86)\Wazuh",
                @"C:\Program Files (x86)\Wazuh Agent"
            });
                    break;
            }

            return directories.Where(Directory.Exists).ToList();
        }

        private static bool CheckIfServiceExists(string serviceName)
        {
            if (serviceName.Equals("Fibratus", StringComparison.OrdinalIgnoreCase))
            {
                return ServiceExists("Fibratus");
            }
            else if (serviceName.Equals("Velociraptor", StringComparison.OrdinalIgnoreCase) ||
                     serviceName.Equals("Nova EDR", StringComparison.OrdinalIgnoreCase))
            {
                return ServiceExists("Velociraptor");
            }
            else if (serviceName.Equals("Wazuh", StringComparison.OrdinalIgnoreCase))
            {
                return ServiceExists("Wazuh") || ServiceExists("wazuh-agent") || ServiceExists("WazuhSvc");
            }

            return false;
        }

        private static bool ServiceExists(string serviceName)
        {
            try
            {
                using (var service = new ServiceController(serviceName))
                {
                    // Just access a property to see if it throws
                    var status = service.Status;
                    return true;
                }
            }
            catch
            {
                return false;
            }
        }

        private static void RemoveService(string serviceName)
        {
            if (serviceName.Equals("Fibratus", StringComparison.OrdinalIgnoreCase))
            {
                StopAndRemoveService("Fibratus");
            }
            else if (serviceName.Equals("Velociraptor", StringComparison.OrdinalIgnoreCase) ||
                     serviceName.Equals("Nova EDR", StringComparison.OrdinalIgnoreCase))
            {
                StopAndRemoveService("Velociraptor");
            }
            else if (serviceName.Equals("Wazuh", StringComparison.OrdinalIgnoreCase))
            {
                StopAndRemoveService("Wazuh");
                StopAndRemoveService("wazuh-agent");
                StopAndRemoveService("WazuhSvc");
            }
        }

        private static void StopAndRemoveService(string serviceName)
        {
            try
            {
                // First try to stop the service gracefully
                try
                {
                    Console.WriteLine($"Stopping service {serviceName}...");
                    StartProcess("net", $"stop {serviceName}");
                }
                catch
                {
                    // Ignore errors stopping the service
                }

                // Then remove the service
                Console.WriteLine($"Removing service {serviceName}...");
                StartProcess("sc", $"delete {serviceName}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error removing service {serviceName}: {ex.Message}");
            }
        }

        private static void CleanupProductDirectory(string productName)
        {
            if (productName.Equals("Fibratus", StringComparison.OrdinalIgnoreCase))
            {
                DeleteDirectory(@"C:\Program Files\Fibratus");
            }
            else if (productName.Equals("Velociraptor", StringComparison.OrdinalIgnoreCase) ||
                     productName.Equals("Nova EDR", StringComparison.OrdinalIgnoreCase))
            {
                DeleteDirectory(@"C:\Program Files\Velociraptor");
            }
            else if (productName.Equals("Wazuh", StringComparison.OrdinalIgnoreCase))
            {
                DeleteDirectory(@"C:\Program Files\Wazuh");
                DeleteDirectory(@"C:\Program Files\Wazuh Agent");
                DeleteDirectory(@"C:\Program Files (x86)\Wazuh");
                DeleteDirectory(@"C:\Program Files (x86)\Wazuh Agent");
            }
        }

        private static void DeleteDirectory(string path)
        {
            if (!Directory.Exists(path)) return;

            try
            {
                Console.WriteLine($"Deleting directory: {path}");
                Directory.Delete(path, true);
                Console.WriteLine($"Successfully deleted directory: {path}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error deleting directory {path}: {ex.Message}");

                // Try forceful deletion with cmd
                try
                {
                    Console.WriteLine("Attempting forceful deletion...");
                    StartProcess("cmd.exe", $"/c rd /s /q \"{path}\"");
                }
                catch
                {
                    // Ignore errors in forceful deletion
                }
            }
        }

        // Keep for compatibility with other parts of the code
        private static void RunMsiProcess(string fileName, string arguments)
        {
            using (var process = new Process())
            {
                process.StartInfo.FileName = fileName;
                process.StartInfo.Arguments = arguments;
                process.StartInfo.UseShellExecute = true;
                process.StartInfo.Verb = "runas";
                process.StartInfo.CreateNoWindow = false;
                process.Start();
                process.WaitForExit();

                if (process.ExitCode != 0 && process.ExitCode != 3010 && process.ExitCode != 1605)
                {
                    throw new Exception($"Process exited with code {process.ExitCode}");
                }
            }
        }
    }
    [RunInstaller(true)]
    public class NovaEDRAgentInstaller : Installer
    {
        public NovaEDRAgentInstaller()
        {
            var serviceInstaller = new ServiceInstaller
            {
                ServiceName = "NovaEDRAgent",
                DisplayName = "Nova EDR Agent",
                Description = "Manages Nova EDR security components and updates",
                StartType = ServiceStartMode.Automatic
            };

            // Add recovery options
            serviceInstaller.Context = new InstallContext();
            serviceInstaller.Context.Parameters["SC_RESTART_DELAY"] = "60000"; // 1 minute
            serviceInstaller.Context.Parameters["SC_ACTIONS"] = "restart/60000/restart/60000/restart/60000/run/1000";

            var processInstaller = new ServiceProcessInstaller
            {
                Account = ServiceAccount.LocalSystem
            };

            Installers.Add(processInstaller);
            Installers.Add(serviceInstaller);

            // Handle Custom Actions during install and uninstall
            AfterInstall += OnAfterInstall;
            BeforeUninstall += OnBeforeUninstall;
        }

        private void OnAfterInstall(object sender, InstallEventArgs e)
        {
            try
            {
                // Create necessary directories
                string logPath = @"C:\ProgramData\NovaEDR\Logs";
                string configPath = @"C:\ProgramData\NovaEDR\Config";
                string tempPath = @"C:\ProgramData\NovaEDR\Temp";

                if (!Directory.Exists(logPath)) Directory.CreateDirectory(logPath);
                if (!Directory.Exists(configPath)) Directory.CreateDirectory(configPath);
                if (!Directory.Exists(tempPath)) Directory.CreateDirectory(tempPath);

                // Verify config file exists and is valid
                string configFilePath = Path.Combine(configPath, "config.json");
                string serverUrl = "http://localhost/Repo";
                string clientId = "default";

                if (File.Exists(configFilePath))
                {
                    try
                    {
                        var configData = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(File.ReadAllText(configFilePath));
                        if (configData.TryGetValue("ServerUrl", out var urlValue))
                        {
                            serverUrl = urlValue.GetString();
                        }
                        if (configData.TryGetValue("ClientId", out var clientValue))
                        {
                            clientId = clientValue.GetString();
                        }

                        File.AppendAllText(Path.Combine(logPath, "install.log"),
                            $"[{DateTime.Now}] Found existing config values: ServerUrl={serverUrl}, ClientId={clientId}\r\n");
                    }
                    catch (Exception configEx)
                    {
                        File.AppendAllText(Path.Combine(logPath, "install.log"),
                            $"[{DateTime.Now}] Error reading config file: {configEx.Message}, using defaults\r\n");
                    }
                }
                else
                {
                    // Create a new config file if it doesn't exist
                    var config = new Dictionary<string, object>
                {
                    { "ServerUrl", serverUrl },
                    { "ClientId", clientId },
                    { "UpdateIntervalMinutes", Constants.DEFAULT_UPDATE_INTERVAL_MINUTES },
                    { "LogLevel", "Info" },
                    { "LogPath", logPath },
                    { "ConfigPath", configPath },
                    { "TempPath", tempPath }
                };

                    File.WriteAllText(configFilePath, JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true }));
                    File.AppendAllText(Path.Combine(logPath, "install.log"),
                        $"[{DateTime.Now}] Created new config file with defaults: ServerUrl={serverUrl}, ClientId={clientId}\r\n");
                }

                // Log what we're about to do
                File.AppendAllText(Path.Combine(logPath, "install.log"),
                    $"[{DateTime.Now}] Starting service initialization with ServerUrl={serverUrl}, ClientId={clientId}\r\n");

                // Configure service recovery
                try
                {
                    // Use SC.exe to configure recovery options
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = "sc.exe",
                        Arguments = "failure NovaEDRAgent reset= 86400 actions= restart/60000/restart/60000/restart/60000",
                        UseShellExecute = true,
                        Verb = "runas",
                        CreateNoWindow = true
                    }).WaitForExit();

                    File.AppendAllText(Path.Combine(logPath, "install.log"),
                        $"[{DateTime.Now}] Configured service recovery options\r\n");
                }
                catch (Exception scEx)
                {
                    File.AppendAllText(Path.Combine(logPath, "install.log"),
                        $"[{DateTime.Now}] Error configuring service recovery: {scEx.Message}\r\n");
                }

                // Start the service
                try
                {
                    using (var controller = new ServiceController("NovaEDRAgent"))
                    {
                        if (controller.Status == ServiceControllerStatus.Stopped)
                        {
                            controller.Start();
                            Console.WriteLine("Service started successfully");
                            File.AppendAllText(Path.Combine(logPath, "install.log"),
                                $"[{DateTime.Now}] Service started successfully\r\n");
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error starting service: {ex.Message}");
                    File.AppendAllText(Path.Combine(logPath, "install.log"),
                        $"[{DateTime.Now}] Error starting service: {ex.Message}\r\n{ex.StackTrace}\r\n");
                }
            }
            catch (Exception ex)
            {
                string message = $"Error during post-install: {ex.Message}";
                Console.WriteLine(message);

                try
                {
                    string logPath = @"C:\ProgramData\NovaEDR\Logs";
                    if (!Directory.Exists(logPath)) Directory.CreateDirectory(logPath);

                    File.AppendAllText(Path.Combine(logPath, "install_error.log"),
                        $"[{DateTime.Now}] {message}\r\n{ex.StackTrace}\r\n");
                }
                catch
                {
                    // Suppress errors in error handling
                }
            }
        }

        private void OnBeforeUninstall(object sender, InstallEventArgs e)
        {
            try
            {
                // Stop the service first
                using (var controller = new ServiceController("NovaEDRAgent"))
                {
                    if (controller.Status != ServiceControllerStatus.Stopped)
                    {
                        controller.Stop();
                        controller.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
                    }
                }
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("NovaEDR", $"Error during pre-uninstall: {ex.Message}", EventLogEntryType.Error);
            }
        }
    }

    public class NovaEDRAgent : ServiceBase
    {
        private readonly HttpClient _httpClient;
        private readonly Logger _logger;
        private readonly ConfigManager _config;
        private CancellationTokenSource _cancelTokenSource;
        private Task _mainTask;
        private bool _isFirstRun = true;

        // Embedded update service
        private readonly UpdateService _updateService;

        // Status tracking
        private readonly StatusReporter _statusReporter;

        // Constants
        private const string SERVICE_NAME = "NovaEDRAgent";
        private const string DISPLAY_NAME = "Nova EDR Agent";
        private const string EVENT_SOURCE = "NovaEDR";
        private const string EVENT_LOG = "Application";

        public NovaEDRAgent()
        {
            ServiceName = SERVICE_NAME;
            AutoLog = false;

            // Initialize HttpClient with TLS 1.2 support
            var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true // For testing only, remove in production
            };
            _httpClient = new HttpClient(handler);
            _httpClient.Timeout = TimeSpan.FromMinutes(10); // Long timeout for large file downloads

            // Initialize logger
            _logger = new Logger(EVENT_SOURCE, EVENT_LOG);

            // Initialize configuration
            _config = new ConfigManager();

            // Initialize update service
            _updateService = new UpdateService(_httpClient, _logger, _config);

            // Initialize status reporter
            _statusReporter = new StatusReporter(_httpClient, _logger, _config);

            // Set up event handlers
            CanHandlePowerEvent = true;
            CanHandleSessionChangeEvent = true;
            CanShutdown = true;
            CanStop = true;
        }
        protected override void OnStart(string[] args)
        {
            _logger.Info("Nova EDR Agent starting");

            try
            {
                // Load configuration
                _config.Load();
                // Force update interval to be 15 minutes
                _logger.Info($"Loaded update interval: {_config.UpdateIntervalMinutes} minutes");
                if (_config.UpdateIntervalMinutes != Constants.DEFAULT_UPDATE_INTERVAL_MINUTES)
                {
                    _logger.Warning($"Update interval incorrect ({_config.UpdateIntervalMinutes}), forcing to {Constants.DEFAULT_UPDATE_INTERVAL_MINUTES} minutes");
                    _config.UpdateIntervalMinutes = Constants.DEFAULT_UPDATE_INTERVAL_MINUTES;
                    _config.Save(); // Make sure this change persists
                }
                _logger.Info($"Using update interval: {_config.UpdateIntervalMinutes} minutes");

                // Initialize cancellation token
                _cancelTokenSource = new CancellationTokenSource();

                // Start main service task
                _mainTask = Task.Run(() => MainServiceLoop(_cancelTokenSource.Token));

                _logger.Info("Nova EDR Agent started successfully");
            }
            catch (Exception ex)
            {
                _logger.Error($"Failed to start Nova EDR Agent: {ex.Message}", ex);
                Stop();
            }
        }

        public void StartConsole(string[] args)
        {
            _logger.Info("Nova EDR Agent starting in console mode");

            try
            {
                // Parse console arguments
                if (args.Length > 1)
                {
                    if (args[1].Equals("--update", StringComparison.OrdinalIgnoreCase))
                    {
                        _logger.Info("Running immediate update");
                        _config.Load();
                        _updateService.PerformUpdate(true).Wait();
                        _logger.Info("Update completed");
                        return;
                    }
                    else if (args[1].Equals("--status", StringComparison.OrdinalIgnoreCase))
                    {
                        _logger.Info("Checking component status");
                        _config.Load();
                        var status = _statusReporter.CollectStatusInfo();
                        Console.WriteLine(JsonSerializer.Serialize(status, new JsonSerializerOptions { WriteIndented = true }));
                        return;
                    }
                }

                // Start like a service but in console
                OnStart(args);

                // Keep console open
                Console.WriteLine("Nova EDR Agent running. Press Ctrl+C to stop.");
                Console.CancelKeyPress += (sender, e) =>
                {
                    e.Cancel = true;
                    OnStop();
                };
            }
            catch (Exception ex)
            {
                _logger.Error($"Failed to start Nova EDR Agent in console mode: {ex.Message}", ex);
            }
        }
        protected override void OnStop()
        {
            _logger.Info("Nova EDR Agent stopping");

            try
            {
                // Signal the main loop to stop
                _cancelTokenSource?.Cancel();

                // Wait for the main task to complete
                if (_mainTask != null)
                {
                    _mainTask.Wait(TimeSpan.FromSeconds(30));
                }

                _statusReporter.ReportStatus("Stopped");
                _logger.Info("Nova EDR Agent stopped successfully");
            }
            catch (Exception ex)
            {
                _logger.Error($"Error during Nova EDR Agent shutdown: {ex.Message}", ex);
            }
        }

        private async Task MainServiceLoop(CancellationToken cancellationToken)
        {
            _logger.Info("Main service loop started");

            try
            {
                // Report startup
                await _statusReporter.ReportStatus("Started");

                // Initial update check
                if (_isFirstRun)
                {
                    _logger.Info("Performing initial update check");
                    await _updateService.PerformUpdate(false);
                    _isFirstRun = false;

                    // Explicitly log the update interval for debugging
                    _logger.Info($"Using update interval of {_config.UpdateIntervalMinutes} minutes");
                }

                // Main service loop
                while (!cancellationToken.IsCancellationRequested)
                {
                    try
                    {
                        // Check component status
                        _logger.Info("Checking component status");
                        await InternalCheckComponentStatus();

                        // Now check for updates on the configured interval
                        _logger.Info("Checking for updates");
                        await _updateService.PerformUpdate(false);
                        _logger.Info("Performing MANDATORY Fibratus restart after update check");
                        try
                        {
                            bool fibratusRunning = false;

                            // Check if Fibratus is installed
                            try
                            {
                                using (var service = new ServiceController("Fibratus"))
                                {
                                    fibratusRunning = (service.Status == ServiceControllerStatus.Running);

                                    // Stop Fibratus if it's running
                                    if (fibratusRunning)
                                    {
                                        _logger.Info("Stopping Fibratus service for mandatory restart");
                                        service.Stop();
                                        service.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
                                        _logger.Info("Fibratus service stopped successfully");
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                _logger.Warning($"Error checking/stopping Fibratus: {ex.Message}");
                                fibratusRunning = false;
                            }

                            // Give it a moment to fully stop
                            await Task.Delay(3000);

                            // Only try to start if we found it running before
                            if (fibratusRunning)
                            {
                                try
                                {
                                    using (var service = new ServiceController("Fibratus"))
                                    {
                                        _logger.Info("Starting Fibratus service after mandatory restart");
                                        service.Start();
                                        service.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
                                        _logger.Info("Fibratus service started successfully after mandatory restart");
                                    }
                                }
                                catch (Exception ex)
                                {
                                    _logger.Error($"Error starting Fibratus after mandatory restart: {ex.Message}");

                                    // Emergency restart using command line
                                    try
                                    {
                                        _logger.Info("Attempting emergency restart of Fibratus via command line");
                                        Process.Start(new ProcessStartInfo
                                        {
                                            FileName = "cmd.exe",
                                            Arguments = "/c net start Fibratus",
                                            UseShellExecute = true,
                                            Verb = "runas",
                                            CreateNoWindow = true
                                        });
                                    }
                                    catch (Exception cmdEx)
                                    {
                                        _logger.Error($"Emergency restart command failed: {cmdEx.Message}");
                                    }
                                }
                            }
                            else
                            {
                                _logger.Warning("Fibratus was not running or not found, skipping restart");
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.Error($"Critical error during Fibratus restart: {ex.Message}", ex);
                        }

                        if (!cancellationToken.IsCancellationRequested)
                        {
                            // Always use exactly the configured interval
                            int waitMinutes = Constants.DEFAULT_UPDATE_INTERVAL_MINUTES; // Use the constant to ensure consistency
                            _logger.Info($"Waiting EXACTLY {waitMinutes} minutes until next update check");
                            await Task.Delay(TimeSpan.FromMinutes(waitMinutes), cancellationToken);

                            // Report status after update check
                            await _statusReporter.ReportStatus("Running");
                        }
                    }
                    catch (TaskCanceledException)
                    {
                        // Expected during cancellation, do nothing
                    }
                    catch (Exception ex)
                    {
                        _logger.Error($"Error in main service loop: {ex.Message}", ex);
                        await Task.Delay(TimeSpan.FromMinutes(1), cancellationToken);
                    }
                }
            }
            catch (TaskCanceledException)
            {
                // Expected during cancellation, do nothing
            }
            catch (Exception ex)
            {
                _logger.Error($"Critical error in main service loop: {ex.Message}", ex);
            }

            _logger.Info("Main service loop ended");
        }

        private async Task InternalCheckComponentStatus()
        {
            try
            {
                var componentStatus = new Dictionary<string, string>();

                // Check Fibratus
                try
                {
                    var service = new ServiceController("Fibratus");
                    componentStatus["Fibratus"] = service.Status.ToString();
                }
                catch
                {
                    componentStatus["Fibratus"] = "NotInstalled";
                }

                // Check Velociraptor
                try
                {
                    var service = new ServiceController("Velociraptor");
                    componentStatus["Velociraptor"] = service.Status.ToString();
                }
                catch
                {
                    componentStatus["Velociraptor"] = "NotInstalled";
                }

                // Check Wazuh - try multiple service names
                bool wazuhFound = false;
                foreach (string name in new[] { "Wazuh", "wazuh-agent", "WazuhSvc" })
                {
                    try
                    {
                        var service = new ServiceController(name);
                        componentStatus["Wazuh"] = service.Status.ToString();
                        wazuhFound = true;
                        break;
                    }
                    catch
                    {
                        // Service not found, try next name
                    }
                }

                // If no service found, check for Wazuh installation by directories
                if (!wazuhFound)
                {
                    componentStatus["Wazuh"] = "NotInstalled";

                    // Check program files directories
                    string[] possiblePaths = {
                    @"C:\Program Files\Wazuh",
                    @"C:\Program Files\Wazuh Agent",
                    @"C:\Program Files (x86)\Wazuh",
                    @"C:\Program Files (x86)\Wazuh Agent"
                };

                    foreach (string path in possiblePaths)
                    {
                        if (Directory.Exists(path))
                        {
                            componentStatus["Wazuh"] = "Unknown";
                            break;
                        }
                    }
                }

                // If any component is not running, attempt to restart it
                foreach (var component in componentStatus)
                {
                    if (component.Value != "Running")
                    {
                        _logger.Warning($"Component {component.Key} is not running (Status: {component.Value}), attempting to restart");
                        bool success = await _updateService.RestartComponent(component.Key);
                        if (success)
                        {
                            _logger.Info($"Successfully restarted {component.Key}");
                        }
                        else
                        {
                            _logger.Error($"Failed to restart {component.Key}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.Error($"Error checking component status: {ex.Message}", ex);
            }
        }
    }
    #region Support Classes

    public class ConfigManager
    {
        private const string CONFIG_FILE_NAME = "config.json";
        private const string DEFAULT_LOG_PATH = @"C:\ProgramData\NovaEDR\Logs";
        private const string DEFAULT_CONFIG_PATH = @"C:\ProgramData\NovaEDR\Config";
        private const string DEFAULT_TEMP_PATH = @"C:\ProgramData\NovaEDR\Temp";
        private const string VERSION_FILE = "version.json";

        // Default values
        private const string DEFAULT_CLIENT_ID = Constants.DEFAULT_CLIENT_ID; // Use the default from Constants
                                                                              // Using constants from the Constants class

        // Configuration properties
        public string ServerUrl { get; private set; }
        public string ClientId { get; private set; }
        public int UpdateIntervalMinutes { get; set; } // Changed to public set to allow modification
        public string LogPath { get; private set; }
        public string ConfigPath { get; private set; }
        public string TempPath { get; private set; }
        public string AgentVersion { get; private set; }
        public string LogLevel { get; private set; }
        public string WazuhGroups { get; private set; } = "";

        // Component versions
        public Dictionary<string, string> ComponentVersions { get; private set; }

        public ConfigManager()
        {
            // Set default values
            ServerUrl = Constants.SERVER_URL; // Always use the hardcoded server URL
            ClientId = DEFAULT_CLIENT_ID;
            UpdateIntervalMinutes = Constants.DEFAULT_UPDATE_INTERVAL_MINUTES;
            LogPath = DEFAULT_LOG_PATH;
            ConfigPath = DEFAULT_CONFIG_PATH;
            TempPath = DEFAULT_TEMP_PATH;
            AgentVersion = GetAssemblyVersion();
            LogLevel = "Info";
            ComponentVersions = new Dictionary<string, string>();

            // Ensure directories exist
            EnsureDirectoriesExist();
        }

        public void Load()
        {
            try
            {
                // Log current process information
                var currentUser = WindowsIdentity.GetCurrent().Name;
                EventLog.WriteEntry("NovaEDR", $"Loading configuration as user: {currentUser}", EventLogEntryType.Information);

                // Read from config file
                string configFilePath = Path.Combine(ConfigPath, CONFIG_FILE_NAME);
                if (File.Exists(configFilePath))
                {
                    EventLog.WriteEntry("NovaEDR", "Config file found, reading values", EventLogEntryType.Information);

                    string jsonContent = File.ReadAllText(configFilePath);
                    var configData = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(jsonContent);

                    // ServerUrl is hardcoded, ignore any value in config file
                    ServerUrl = Constants.SERVER_URL;

                    if (configData.TryGetValue("ClientId", out var clientId))
                        ClientId = clientId.GetString();

                    // Look for either UpdateIntervalMinutes (new) or UpdateIntervalHours (legacy)
                    if (configData.TryGetValue("UpdateIntervalMinutes", out var updateIntervalMins))
                        UpdateIntervalMinutes = updateIntervalMins.GetInt32();
                    else if (configData.TryGetValue("UpdateIntervalHours", out var updateIntervalHours))
                        UpdateIntervalMinutes = updateIntervalHours.GetInt32() * 60; // Convert hours to minutes

                    if (configData.TryGetValue("LogPath", out var logPath))
                        LogPath = logPath.GetString();

                    if (configData.TryGetValue("ConfigPath", out var configPath))
                        ConfigPath = configPath.GetString();

                    if (configData.TryGetValue("TempPath", out var tempPath))
                        TempPath = tempPath.GetString();

                    if (configData.TryGetValue("LogLevel", out var logLevel))
                        LogLevel = logLevel.GetString();

                    if (configData.TryGetValue("WazuhGroups", out var wazuhGroups))
                        WazuhGroups = wazuhGroups.GetString();

                    // Validate update interval
                    if (UpdateIntervalMinutes <= 0 || UpdateIntervalMinutes > 1440)
                    {
                        UpdateIntervalMinutes = Constants.DEFAULT_UPDATE_INTERVAL_MINUTES;
                        EventLog.WriteEntry("NovaEDR", $"Invalid UpdateIntervalMinutes, reset to default: {UpdateIntervalMinutes}", EventLogEntryType.Warning);
                    }

                    EventLog.WriteEntry("NovaEDR", $"Loaded values: ServerUrl={ServerUrl}, ClientId={ClientId}, UpdateIntervalMinutes={UpdateIntervalMinutes}", EventLogEntryType.Information);
                }
                else
                {
                    EventLog.WriteEntry("NovaEDR", "Config file not found, creating default config", EventLogEntryType.Warning);

                    // Create a new configuration file with default values
                    var configData = new Dictionary<string, object>
                {
                    { "ServerUrl", ServerUrl }, // This is the hardcoded value
                    { "ClientId", ClientId },
                    { "UpdateIntervalMinutes", UpdateIntervalMinutes },
                    { "LogPath", LogPath },
                    { "ConfigPath", ConfigPath },
                    { "TempPath", TempPath },
                    { "LogLevel", LogLevel }
                };

                    string json = JsonSerializer.Serialize(configData, new JsonSerializerOptions { WriteIndented = true });
                    File.WriteAllText(configFilePath, json);
                    EventLog.WriteEntry("NovaEDR", "Created config file with default values", EventLogEntryType.Information);
                }

                // Ensure directories exist after loading config
                EnsureDirectoriesExist();

                // Load component versions from version file
                LoadComponentVersions();

                // Log configuration summary
                EventLog.WriteEntry("NovaEDR",
                    $"Configuration loaded: Server={ServerUrl}, Client={ClientId}, " +
                    $"UpdateInterval={UpdateIntervalMinutes}m, LogPath={LogPath}",
                    EventLogEntryType.Information);

                // Create a log file entry
                try
                {
                    if (!Directory.Exists(LogPath))
                        Directory.CreateDirectory(LogPath);

                    File.AppendAllText(Path.Combine(LogPath, "config.log"),
                        $"[{DateTime.Now}] Configuration loaded: ServerUrl={ServerUrl}, ClientId={ClientId}, UpdateIntervalMinutes={UpdateIntervalMinutes}\r\n");
                }
                catch
                {
                    // Suppress errors in logging
                }
            }
            catch (Exception ex)
            {
                // Log to event log since logger might not be initialized yet
                EventLog.WriteEntry("NovaEDR", $"Error loading configuration: {ex.Message}", EventLogEntryType.Error);
                File.WriteAllText(Path.Combine(DEFAULT_LOG_PATH, "config_error.log"), $"{DateTime.Now}: {ex.Message}\n{ex.StackTrace}");
            }
        }

        public void Save()
        {
            try
            {
                // Save to config file
                string configFilePath = Path.Combine(ConfigPath, CONFIG_FILE_NAME);
                var configData = new Dictionary<string, object>
            {
                { "ServerUrl", ServerUrl }, // This will be the hardcoded value
                { "ClientId", ClientId },
                { "WazuhGroups", WazuhGroups },
                { "UpdateIntervalMinutes", UpdateIntervalMinutes },
                { "LogPath", LogPath },
                { "ConfigPath", ConfigPath },
                { "TempPath", TempPath },
                { "LogLevel", LogLevel }
            };

                string json = JsonSerializer.Serialize(configData, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(configFilePath, json);

                // Save component versions to version file
                SaveComponentVersions();
            }
            catch (Exception ex)
            {
                // Log to event log since logger might not be initialized yet
                EventLog.WriteEntry("NovaEDR", $"Error saving configuration: {ex.Message}", EventLogEntryType.Error);
            }
        }

        public void UpdateComponentVersion(string component, string version)
        {
            if (ComponentVersions.ContainsKey(component))
            {
                ComponentVersions[component] = version;
            }
            else
            {
                ComponentVersions.Add(component, version);
            }

            // Save updated versions
            SaveComponentVersions();
        }

        private void LoadComponentVersions()
        {
            var versionFile = Path.Combine(ConfigPath, VERSION_FILE);

            if (File.Exists(versionFile))
            {
                try
                {
                    var json = File.ReadAllText(versionFile);
                    var versions = JsonSerializer.Deserialize<Dictionary<string, string>>(json);
                    ComponentVersions = versions ?? new Dictionary<string, string>();
                }
                catch
                {
                    // If loading fails, initialize a new dictionary
                    ComponentVersions = new Dictionary<string, string>();
                }
            }
            else
            {
                ComponentVersions = new Dictionary<string, string>();
            }
        }

        private void SaveComponentVersions()
        {
            var versionFile = Path.Combine(ConfigPath, VERSION_FILE);

            try
            {
                var json = JsonSerializer.Serialize(ComponentVersions);
                File.WriteAllText(versionFile, json);
            }
            catch (Exception ex)
            {
                // Log to event log since logger might not be initialized yet
                EventLog.WriteEntry("NovaEDR", $"Error saving component versions: {ex.Message}", EventLogEntryType.Error);
            }
        }

        private void EnsureDirectoriesExist()
        {
            try
            {
                if (!Directory.Exists(LogPath))
                    Directory.CreateDirectory(LogPath);

                if (!Directory.Exists(ConfigPath))
                    Directory.CreateDirectory(ConfigPath);

                if (!Directory.Exists(TempPath))
                    Directory.CreateDirectory(TempPath);
            }
            catch (Exception ex)
            {
                // Log to event log since logger might not be initialized yet
                EventLog.WriteEntry("NovaEDR", $"Error creating directories: {ex.Message}", EventLogEntryType.Error);
            }
        }

        private string GetAssemblyVersion()
        {
            try
            {
                return Assembly.GetExecutingAssembly().GetName().Version.ToString();
            }
            catch
            {
                return "1.0.0.0";
            }
        }
    }

    public class Logger
    {
        private readonly string _source;
        private readonly string _log;
        private readonly string _logFilePath;

        public Logger(string source, string log)
        {
            _source = source;
            _log = log;

            // Ensure event source exists
            if (!EventLog.SourceExists(source))
            {
                try
                {
                    EventLog.CreateEventSource(source, log);
                }
                catch
                {
                    // May fail if not running as admin, but we'll still use file logging
                }
            }

            // Set up file logging
            var logDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "NovaEDR", "Logs");
            if (!Directory.Exists(logDir))
                Directory.CreateDirectory(logDir);

            _logFilePath = Path.Combine(logDir, $"NovaEDRAgent_{DateTime.Now:yyyyMMdd}.log");
        }

        public void Info(string message)
        {
            WriteToEventLog(message, EventLogEntryType.Information);
            WriteToFile("INFO", message);
        }

        public void Warning(string message)
        {
            WriteToEventLog(message, EventLogEntryType.Warning);
            WriteToFile("WARNING", message);
        }

        public void Error(string message, Exception ex = null)
        {
            string fullMessage = message;

            if (ex != null)
            {
                fullMessage += $"\nException: {ex.Message}\nStack Trace: {ex.StackTrace}";
                if (ex.InnerException != null)
                {
                    fullMessage += $"\nInner Exception: {ex.InnerException.Message}";
                }
            }

            WriteToEventLog(fullMessage, EventLogEntryType.Error);
            WriteToFile("ERROR", fullMessage);
        }

        private void WriteToEventLog(string message, EventLogEntryType entryType)
        {
            try
            {
                EventLog.WriteEntry(_source, message, entryType);
            }
            catch
            {
                // Fail silently if event log writing fails
            }
        }

        private void WriteToFile(string level, string message)
        {
            try
            {
                using (var writer = new StreamWriter(_logFilePath, true))
                {
                    writer.WriteLine($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [{level}] {message}");
                }
            }
            catch
            {
                // Fail silently if file writing fails
            }
        }
    }

    public class UpdateService
    {
        private readonly HttpClient _httpClient;
        private readonly Logger _logger;
        private readonly ConfigManager _config;

        // Component handling
        private readonly Dictionary<string, Func<Task<bool>>> _componentUpdaters;

        // Fibratus specific rule files to remove
        private readonly string[] _fibratusRulesToRemove = new string[]
        {
        "defense_evasion_unsigned_dll_injection_via_remote_thread.yml",
        "defense_evasion_potential_process_injection_via_tainted_memory_section.yml",
        "credential_access_potential_sam_hive_dumping.yml",
        "defense_evasion_dotnet_assembly_loaded_by_unmanaged_process.yml",
        "defense_evasion_hidden_registry_key_creation.yml"
        };

        public UpdateService(HttpClient httpClient, Logger logger, ConfigManager config)
        {
            _httpClient = httpClient;
            _logger = logger;
            _config = config;

            // Initialize component updaters
            _componentUpdaters = new Dictionary<string, Func<Task<bool>>>
        {
            { "Fibratus", UpdateFibratus },
            { "Velociraptor", UpdateVelociraptor },
            { "Wazuh", UpdateWazuh }
        };
        }

        public async Task<bool> PerformUpdate(bool forceUpdate)
        {
            _logger.Info($"Starting update check (ForceUpdate: {forceUpdate})");
            bool success = true;

            try
            {
                // Check for agent updates first
                if (await CheckForAgentUpdate(forceUpdate))
                {
                    _logger.Info("Agent update available, restarting agent");
                    // The update process will restart the service, so we can return here
                    return true;
                }

                // Update components one by one
                foreach (var componentUpdater in _componentUpdaters)
                {
                    try
                    {
                        _logger.Info($"Checking for {componentUpdater.Key} updates");
                        if (!await componentUpdater.Value())
                        {
                            _logger.Warning($"Update check for {componentUpdater.Key} failed");
                            success = false;
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.Error($"Error updating {componentUpdater.Key}: {ex.Message}", ex);
                        success = false;
                    }
                }

                _logger.Info($"Update check completed. Success: {success}");
                return success;
            }
            catch (Exception ex)
            {
                _logger.Error($"Error during update check: {ex.Message}", ex);
                return false;
            }
        }

        public async Task<bool> RestartComponent(string componentName)
        {
            _logger.Info($"Attempting to restart {componentName}");

            try
            {
                // More aggressive restart approach
                switch (componentName.ToLower())
                {
                    case "fibratus":
                        return await ForceRestartService("Fibratus");

                    case "velociraptor":
                        return await ForceRestartService("Velociraptor");

                    case "wazuh":
                        // Try to find the correct Wazuh service name
                        string wazuhServiceName = null;

                        // Try the various possible service names for Wazuh
                        string[] possibleNames = { "Wazuh", "wazuh-agent", "WazuhSvc" };
                        foreach (string name in possibleNames)
                        {
                            if (IsServiceInstalled(name))
                            {
                                wazuhServiceName = name;
                                break;
                            }
                        }

                        if (!string.IsNullOrEmpty(wazuhServiceName))
                        {
                            return await ForceRestartService(wazuhServiceName);
                        }
                        else
                        {
                            // Try each possible name
                            foreach (string name in possibleNames)
                            {
                                if (await TryStartService(name))
                                {
                                    return true;
                                }
                            }
                            _logger.Warning("Could not find Wazuh service to restart");
                            return false;
                        }

                    default:
                        _logger.Warning($"Unknown component name: {componentName}");
                        return false;
                }
            }
            catch (Exception ex)
            {
                _logger.Error($"Error restarting {componentName}: {ex.Message}", ex);

                // Last resort - use net stop/start commands
                try
                {
                    _logger.Info($"Attempting to restart {componentName} with net commands");

                    // For Wazuh, try to find the correct service name
                    string actualServiceName = componentName;
                    if (componentName.ToLower() == "wazuh")
                    {
                        // Try the various possible service names for Wazuh
                        string[] possibleNames = { "Wazuh", "wazuh-agent", "WazuhSvc" };
                        foreach (string name in possibleNames)
                        {
                            if (IsServiceInstalled(name))
                            {
                                actualServiceName = name;
                                break;
                            }
                        }
                    }

                    Process.Start(new ProcessStartInfo
                    {
                        FileName = "net",
                        Arguments = $"stop {actualServiceName}",
                        UseShellExecute = true,
                        Verb = "runas"
                    }).WaitForExit();

                    Thread.Sleep(2000); // Wait 2 seconds between stop and start

                    Process.Start(new ProcessStartInfo
                    {
                        FileName = "net",
                        Arguments = $"start {actualServiceName}",
                        UseShellExecute = true,
                        Verb = "runas"
                    }).WaitForExit();

                    return true;
                }
                catch (Exception netEx)
                {
                    _logger.Error($"Error restarting {componentName} with net commands: {netEx.Message}");
                    return false;
                }
            }
        }

        private async Task<bool> ForceRestartService(string serviceName)
        {
            _logger.Info($"Force restarting service {serviceName}");

            try
            {
                // First try to stop the service properly
                await StopService(serviceName);

                // Wait a bit longer for the service to fully stop
                Thread.Sleep(3000);  // Increased from 2000ms to 3000ms

                // Check if the service is truly stopped before attempting to start
                using (var checkService = new ServiceController(serviceName))
                {
                    checkService.Refresh();
                    if (checkService.Status != ServiceControllerStatus.Stopped)
                    {
                        _logger.Info($"Service {serviceName} not fully stopped yet. Using SC command to force stop...");
                        // Use SC command to force stop the service
                        Process.Start(new ProcessStartInfo
                        {
                            FileName = "sc.exe",
                            Arguments = $"stop {serviceName}",
                            UseShellExecute = true,
                            Verb = "runas",
                            CreateNoWindow = true
                        }).WaitForExit();

                        Thread.Sleep(3000);  // Wait again after force stop
                    }
                }

                // Now try to start the service
                await StartService(serviceName);

                // Add more verification attempts
                int verificationAttempts = 0;
                bool serviceRunning = false;

                while (!serviceRunning && verificationAttempts < 3)
                {
                    verificationAttempts++;

                    // Verify the service is running
                    using (var service = new ServiceController(serviceName))
                    {
                        service.Refresh();
                        if (service.Status == ServiceControllerStatus.Running)
                        {
                            serviceRunning = true;
                            _logger.Info($"Successfully restarted {serviceName}");
                        }
                        else
                        {
                            _logger.Warning($"Service {serviceName} is in {service.Status} state after restart attempt #{verificationAttempts}");

                            if (verificationAttempts < 3)
                            {
                                _logger.Info($"Waiting and trying again...");
                                Thread.Sleep(2000);

                                if (service.Status == ServiceControllerStatus.Stopped)
                                {
                                    // Try to start again
                                    try
                                    {
                                        service.Start();
                                        await Task.Run(() => service.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30)));
                                    }
                                    catch (Exception ex)
                                    {
                                        _logger.Error($"Error starting service on retry #{verificationAttempts}: {ex.Message}");
                                    }
                                }
                            }
                        }
                    }
                }

                if (!serviceRunning)
                {
                    // Last resort - use net start command
                    _logger.Info($"Final attempt to restart {serviceName} with net start command");
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = "net",
                        Arguments = $"start {serviceName}",
                        UseShellExecute = true,
                        Verb = "runas",
                        CreateNoWindow = true
                    }).WaitForExit();

                    // Final check
                    using (var service = new ServiceController(serviceName))
                    {
                        service.Refresh();
                        return service.Status == ServiceControllerStatus.Running;
                    }
                }

                return serviceRunning;
            }
            catch (Exception ex)
            {
                _logger.Error($"Error in ForceRestartService for {serviceName}: {ex.Message}", ex);

                // Emergency restart attempt using command line
                try
                {
                    _logger.Info($"Emergency restart attempt for {serviceName}");
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = "cmd.exe",
                        Arguments = $"/c net stop {serviceName} && timeout /t 5 && net start {serviceName}",
                        UseShellExecute = true,
                        Verb = "runas"
                    });
                    return true; // Assume it worked since we can't verify in this emergency path
                }
                catch
                {
                    return false;
                }
            }
        }

        private async Task<bool> CheckForAgentUpdate(bool forceUpdate)
        {
            try
            {
                // Check for agent updates from server
                string updateUrl = GetComponentUrl("NovaEDRAgent.json");

                var response = await _httpClient.GetAsync(updateUrl);
                if (!response.IsSuccessStatusCode)
                {
                    // Agent update info not available, just log and continue
                    _logger.Info($"Agent update check skipped - update info not available (Status code: {response.StatusCode})");
                    return false;
                }

                var content = await response.Content.ReadAsStringAsync();
                var updateInfo = JsonSerializer.Deserialize<Dictionary<string, string>>(content);

                if (!updateInfo.TryGetValue("version", out var latestVersion))
                {
                    _logger.Warning("Agent update check failed: Invalid update format");
                    return false;
                }

                // Compare versions
                if (!forceUpdate && Version.Parse(latestVersion) <= Version.Parse(_config.AgentVersion))
                {
                    _logger.Info($"Agent is up to date (Current: {_config.AgentVersion}, Latest: {latestVersion})");
                    return false;
                }

                _logger.Info($"Agent update available: {latestVersion} (Current: {_config.AgentVersion})");

                // Download and apply update
                if (!updateInfo.TryGetValue("url", out var updateFileUrl))
                {
                    _logger.Warning("Agent update check failed: Missing update URL");
                    return false;
                }

                string downloadUrl = GetComponentUrl(updateFileUrl);
                string updateFilePath = Path.Combine(_config.TempPath, "NovaEDRAgent_Update.exe");

                // Download update file
                var updateResponse = await _httpClient.GetAsync(downloadUrl);
                if (!updateResponse.IsSuccessStatusCode)
                {
                    _logger.Warning($"Failed to download agent update. Status code: {updateResponse.StatusCode}");
                    return false;
                }

                using (var fileStream = new FileStream(updateFilePath, FileMode.Create, FileAccess.Write))
                {
                    await updateResponse.Content.CopyToAsync(fileStream);
                }

                _logger.Info($"Downloaded agent update to {updateFilePath}");

                // Verify update file
                if (updateInfo.TryGetValue("hash", out var expectedHash))
                {
                    using (var sha256 = SHA256.Create())
                    using (var stream = File.OpenRead(updateFilePath))
                    {
                        var hash = BitConverter.ToString(sha256.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
                        if (hash != expectedHash.ToLowerInvariant())
                        {
                            _logger.Warning("Agent update file hash verification failed");
                            File.Delete(updateFilePath);
                            return false;
                        }
                    }
                }

                // Execute update process
                _logger.Info("Starting agent update process");

                // Create a batch file to:
                // 1. Stop the service
                // 2. Replace the executable
                // 3. Start the service
                string batchFilePath = Path.Combine(_config.TempPath, "AgentUpdate.bat");
                string servicePath = Process.GetCurrentProcess().MainModule.FileName;

                string batchContent = $@"@echo off
echo Updating Nova EDR Agent...
timeout /t 3 /nobreak > NUL
net stop NovaEDRAgent
timeout /t 2 /nobreak > NUL
copy /Y ""{updateFilePath}"" ""{servicePath}""
timeout /t 1 /nobreak > NUL
net start NovaEDRAgent
timeout /t 1 /nobreak > NUL
del ""{updateFilePath}""
del ""%~f0""
";

                File.WriteAllText(batchFilePath, batchContent);

                // Start the batch file process
                Process.Start(new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = $"/c {batchFilePath}",
                    CreateNoWindow = true,
                    UseShellExecute = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                });

                _logger.Info("Agent update process started");
                return true;
            }
            catch (Exception ex)
            {
                _logger.Error($"Error checking for agent updates: {ex.Message}", ex);
                return false;
            }
        }

        private async Task<bool> UpdateFibratus()
        {
            _logger.Info("Checking for Fibratus updates");

            try
            {
                // Check if Fibratus is installed
                if (!IsServiceInstalled("Fibratus"))
                {
                    _logger.Info("Fibratus is not installed, installing...");
                    return await InstallFibratus();
                }

                // Check for rule updates
                string rulesVersionUrl = GetComponentUrl("Custom-Rules.zip.version");

                var response = await _httpClient.GetAsync(rulesVersionUrl);
                if (!response.IsSuccessStatusCode)
                {
                    _logger.Warning($"Failed to check for Fibratus rule updates. Status code: {response.StatusCode}");
                    return false;
                }

                var latestVersion = await response.Content.ReadAsStringAsync();
                latestVersion = latestVersion.Trim();

                // Get current installed version
                string currentVersion = _config.ComponentVersions.ContainsKey("FibratusRules")
                    ? _config.ComponentVersions["FibratusRules"]
                    : "0";

                // Check if update is needed
                if (latestVersion == currentVersion)
                {
                    _logger.Info($"Fibratus rules are up to date (version: {currentVersion})");
                    return true;
                }

                _logger.Info($"Fibratus rule update available: {latestVersion} (Current: {currentVersion})");

                // Download new rules
                string rulesUrl = GetComponentUrl("Custom-Rules.zip");
                string rulesPath = Path.Combine(_config.TempPath, "Custom-Rules.zip");
                string extractPath = Path.Combine(_config.TempPath, "FibratusRules");

                var rulesResponse = await _httpClient.GetAsync(rulesUrl);
                if (!rulesResponse.IsSuccessStatusCode)
                {
                    _logger.Warning($"Failed to download Fibratus rules. Status code: {rulesResponse.StatusCode}");
                    return false;
                }

                using (var fileStream = new FileStream(rulesPath, FileMode.Create, FileAccess.Write))
                {
                    await rulesResponse.Content.CopyToAsync(fileStream);
                }

                _logger.Info($"Downloaded Fibratus rules to {rulesPath}");

                // Clean up extraction directory if it exists
                if (Directory.Exists(extractPath))
                    Directory.Delete(extractPath, true);

                Directory.CreateDirectory(extractPath);

                // Extract rules
                ZipFile.ExtractToDirectory(rulesPath, extractPath);
                _logger.Info($"Extracted rules to {extractPath}");

                // Stop Fibratus service before updating rules
                _logger.Info("Stopping Fibratus service to update rules...");
                await StopService("Fibratus");

                _logger.Info("Preparing to apply rule updates while preserving default rules");

                // CRITICAL - DO NOT DELETE OR RECREATE THE RULES DIRECTORY
                string fibratusRulesPath = @"C:\Program Files\Fibratus\Rules";

                // Create directories if they don't exist (without deleting anything)
                if (!Directory.Exists(fibratusRulesPath))
                {
                    Directory.CreateDirectory(fibratusRulesPath);
                    _logger.Info("Created Fibratus rules directory");
                }

                // Step 1: Remove specific rule files that should be excluded
                bool rulesChanged = false;
                foreach (var ruleToRemove in _fibratusRulesToRemove)
                {
                    string rulePath = Path.Combine(fibratusRulesPath, ruleToRemove);
                    if (File.Exists(rulePath))
                    {
                        _logger.Info($"Removing excluded rule: {ruleToRemove}");
                        File.Delete(rulePath);
                        rulesChanged = true;
                    }
                }

                // Step 2: Apply custom rule files - only replace existing or add new (NO MACROS HANDLING)
                int newRuleCount = 0;
                int updatedRuleCount = 0;

                var customRuleFiles = Directory.GetFiles(extractPath, "*.yml", SearchOption.AllDirectories)
                    .Where(f => !Path.GetFileName(f).Equals("macros.yml", StringComparison.OrdinalIgnoreCase))
                    .ToList();

                _logger.Info($"Found {customRuleFiles.Count} custom rule files to process (excluding macros.yml)");

                foreach (var customRulePath in customRuleFiles)
                {
                    string fileName = Path.GetFileName(customRulePath);
                    string destPath = Path.Combine(fibratusRulesPath, fileName);

                    bool fileExists = File.Exists(destPath);
                    File.Copy(customRulePath, destPath, true); // Overwrite if exists

                    if (fileExists)
                    {
                        _logger.Info($"Updated rule: {fileName}");
                        updatedRuleCount++;
                    }
                    else
                    {
                        _logger.Info($"Added new rule: {fileName}");
                        newRuleCount++;
                    }
                    rulesChanged = true;
                }

                _logger.Info($"Rule processing complete: {newRuleCount} new rules added, {updatedRuleCount} existing rules updated");

                // Always restart Fibratus after rule updates
                _logger.Info("Restarting Fibratus service after rule updates...");
                await StartService("Fibratus");

                if (rulesChanged)
                {
                    _logger.Info("Detected rule changes - Fibratus restart was required");
                }
                else
                {
                    _logger.Info("No rule changes detected, but restarted Fibratus as a precaution");
                }

                // Update version information
                _config.UpdateComponentVersion("FibratusRules", latestVersion);

                // Cleanup
                File.Delete(rulesPath);
                Directory.Delete(extractPath, true);

                _logger.Info($"Fibratus rules updated to version {latestVersion}");
                return true;
            }
            catch (Exception ex)
            {
                _logger.Error($"Error updating Fibratus: {ex.Message}", ex);

                // Try to restart the service if it was stopped
                try
                {
                    await StartService("Fibratus");
                }
                catch
                {
                    // Ignore errors during restart attempt
                }

                return false;
            }
        }

        private async Task<bool> InstallFibratus()
        {
            try
            {
                _logger.Info("Installing Fibratus");

                // Download Fibratus MSI
                string msiUrl = GetComponentUrl("Fibratus.msi");
                string msiPath = Path.Combine(_config.TempPath, "Fibratus.msi");

                var response = await _httpClient.GetAsync(msiUrl);
                if (!response.IsSuccessStatusCode)
                {
                    _logger.Warning($"Failed to download Fibratus MSI. Status code: {response.StatusCode}");
                    return false;
                }

                using (var fileStream = new FileStream(msiPath, FileMode.Create, FileAccess.Write))
                {
                    await response.Content.CopyToAsync(fileStream);
                }

                _logger.Info($"Downloaded Fibratus MSI to {msiPath}");

                // Install Fibratus
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "msiexec.exe",
                        Arguments = $"/i \"{msiPath}\" /quiet /norestart",
                        CreateNoWindow = true,
                        UseShellExecute = false
                    }
                };

                process.Start();
                await Task.Run(() => process.WaitForExit());

                if (process.ExitCode != 0 && process.ExitCode != 3010)
                {
                    _logger.Warning($"Fibratus installation failed with exit code: {process.ExitCode}");
                    return false;
                }

                _logger.Info("Fibratus installed successfully");

                // After installation, let's apply our custom rules without calling UpdateFibratus again 
                // (which would cause recursion and potentially wipe out official rules)

                try
                {
                    // Download our custom rules
                    string rulesUrl = GetComponentUrl("Custom-Rules.zip");
                    string rulesPath = Path.Combine(_config.TempPath, "Custom-Rules.zip");
                    string extractPath = Path.Combine(_config.TempPath, "FibratusRules");

                    _logger.Info("Downloading custom rules for initial setup");
                    var rulesResponse = await _httpClient.GetAsync(rulesUrl);
                    if (rulesResponse.IsSuccessStatusCode)
                    {
                        using (var fileStream = new FileStream(rulesPath, FileMode.Create, FileAccess.Write))
                        {
                            await rulesResponse.Content.CopyToAsync(fileStream);
                        }

                        _logger.Info($"Downloaded initial custom rules to {rulesPath}");

                        // Extract rules
                        if (Directory.Exists(extractPath))
                            Directory.Delete(extractPath, true);

                        Directory.CreateDirectory(extractPath);
                        ZipFile.ExtractToDirectory(rulesPath, extractPath);

                        // Apply the rules (preserving official rules that come with Fibratus)
                        string fibratusRulesPath = @"C:\Program Files\Fibratus\Rules";

                        // First, remove specific rule files that should be excluded
                        foreach (var ruleToRemove in _fibratusRulesToRemove)
                        {
                            string rulePath = Path.Combine(fibratusRulesPath, ruleToRemove);
                            if (File.Exists(rulePath))
                            {
                                File.Delete(rulePath);
                                _logger.Info($"Removed excluded rule: {ruleToRemove}");
                            }
                        }

                        // Apply our custom rules as needed (NO MACROS HANDLING)
                        var allYmlFiles = Directory.GetFiles(extractPath, "*.yml", SearchOption.AllDirectories);
                        _logger.Info($"Found {allYmlFiles.Length} YML files in initial custom rules package");

                        // Process all custom rule files (excluding macros.yml)
                        foreach (var ymlFile in allYmlFiles)
                        {
                            // Skip the macro file completely - no longer handling it
                            if (Path.GetFileName(ymlFile).Equals("macros.yml", StringComparison.OrdinalIgnoreCase))
                            {
                                _logger.Info("Skipping macros.yml - no longer overwriting default macros");
                                continue;
                            }

                            // Copy the file to the rules directory (will overwrite existing files with same name)
                            string destPath = Path.Combine(fibratusRulesPath, Path.GetFileName(ymlFile));
                            bool fileExists = File.Exists(destPath);
                            File.Copy(ymlFile, destPath, true);

                            if (fileExists)
                            {
                                _logger.Info($"Updated rule: {Path.GetFileName(ymlFile)}");
                            }
                            else
                            {
                                _logger.Info($"Added new rule: {Path.GetFileName(ymlFile)}");
                            }
                        }

                        // Update version information from the server
                        string rulesVersionUrl = GetComponentUrl("Custom-Rules.zip.version");
                        var versionResponse = await _httpClient.GetAsync(rulesVersionUrl);
                        if (versionResponse.IsSuccessStatusCode)
                        {
                            var latestVersion = await versionResponse.Content.ReadAsStringAsync();
                            latestVersion = latestVersion.Trim();
                            _config.UpdateComponentVersion("FibratusRules", latestVersion);
                            _logger.Info($"Updated Fibratus rules version to {latestVersion}");
                        }

                        // Cleanup
                        File.Delete(rulesPath);
                        Directory.Delete(extractPath, true);
                    }
                    else
                    {
                        _logger.Warning($"Failed to download initial custom rules. Status: {rulesResponse.StatusCode}");
                    }
                }
                catch (Exception ex)
                {
                    _logger.Error($"Error applying initial custom rules: {ex.Message}", ex);
                }

                // Clean up
                File.Delete(msiPath);

                // ADDED: Force restart Fibratus after initial installation
                _logger.Info("Forcing Fibratus restart after initial installation");
                try
                {
                    // First stop the service if it's running
                    await StopService("Fibratus");

                    // Wait a moment to ensure complete shutdown
                    await Task.Delay(3000);

                    // Start the service again
                    await StartService("Fibratus");

                    // Verify the service started
                    using (var service = new ServiceController("Fibratus"))
                    {
                        service.Refresh();
                        if (service.Status == ServiceControllerStatus.Running)
                        {
                            _logger.Info("Successfully restarted Fibratus after initial installation");
                        }
                        else
                        {
                            _logger.Warning($"Fibratus status after restart attempt: {service.Status}");
                            // Emergency restart using command line
                            _logger.Info("Attempting emergency restart of Fibratus via command line");
                            Process.Start(new ProcessStartInfo
                            {
                                FileName = "cmd.exe",
                                Arguments = "/c net start Fibratus",
                                UseShellExecute = true,
                                Verb = "runas",
                                CreateNoWindow = true
                            });
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.Error($"Error restarting Fibratus after initial installation: {ex.Message}", ex);
                    // Still continue with return true so the installation process proceeds
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.Error($"Error installing Fibratus: {ex.Message}", ex);
                return false;
            }
        }

        private async Task<bool> UpdateVelociraptor()
        {
            _logger.Info("Checking for Velociraptor updates");

            try
            {
                // Velociraptor doesn't have regular updates like Fibratus rules
                // For now, just check if it's installed and install if needed
                if (!IsServiceInstalled("Velociraptor"))
                {
                    _logger.Info("Velociraptor is not installed, installing...");
                    return await InstallVelociraptor();
                }

                _logger.Info("Velociraptor is already installed and running");
                return true;
            }
            catch (Exception ex)
            {
                _logger.Error($"Error updating Velociraptor: {ex.Message}", ex);
                return false;
            }
        }

        private async Task<bool> InstallVelociraptor()
        {
            try
            {
                _logger.Info("Installing Velociraptor");

                // Download Velociraptor MSI (now renamed to Velo.msi)
                string msiUrl = GetComponentUrl("Velo.msi");
                string msiPath = Path.Combine(_config.TempPath, "Velo.msi");

                var response = await _httpClient.GetAsync(msiUrl);
                if (!response.IsSuccessStatusCode)
                {
                    _logger.Warning($"Failed to download Velociraptor MSI. Status code: {response.StatusCode}");
                    return false;
                }

                using (var fileStream = new FileStream(msiPath, FileMode.Create, FileAccess.Write))
                {
                    await response.Content.CopyToAsync(fileStream);
                }

                _logger.Info($"Downloaded Velociraptor MSI to {msiPath}");

                // Install Velociraptor
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "msiexec.exe",
                        Arguments = $"/i \"{msiPath}\" /quiet /norestart",
                        CreateNoWindow = true,
                        UseShellExecute = false
                    }
                };

                process.Start();
                await Task.Run(() => process.WaitForExit());

                if (process.ExitCode != 0 && process.ExitCode != 3010)
                {
                    _logger.Warning($"Velociraptor installation failed with exit code: {process.ExitCode}");
                    return false;
                }

                _logger.Info("Velociraptor installed successfully");

                // Clean up
                File.Delete(msiPath);

                return true;
            }
            catch (Exception ex)
            {
                _logger.Error($"Error installing Velociraptor: {ex.Message}", ex);
                return false;
            }
        }

        private async Task<bool> UpdateWazuh()
        {
            _logger.Info("Checking for Wazuh updates");

            try
            {
                // First check if Wazuh PowerShell script exists
                string scriptUrl = GetComponentUrl("Wazuh.ps1");

                try
                {
                    var response = await _httpClient.GetAsync(scriptUrl);
                    if (!response.IsSuccessStatusCode)
                    {
                        _logger.Info("Wazuh installation script not found, skipping Wazuh installation");
                        return true;
                    }
                }
                catch
                {
                    _logger.Info("Could not access Wazuh installation script, skipping Wazuh installation");
                    return true;
                }

                // Use dynamic service discovery instead of hardcoded checks
                var wazuhServices = FindWazuhServices();
                bool wazuhInstalled = wazuhServices.Count > 0;

                // Also check for installation directories if no services found
                if (!wazuhInstalled)
                {
                    var wazuhDirectories = GetWazuhDirectories();
                    wazuhInstalled = wazuhDirectories.Count > 0;

                    if (wazuhInstalled)
                    {
                        _logger.Info($"Found Wazuh installation directories: {string.Join(", ", wazuhDirectories)}");
                    }
                }

                // Check for version marker in our config
                if (!wazuhInstalled && _config.ComponentVersions.ContainsKey("Wazuh") &&
                    _config.ComponentVersions["Wazuh"] == "installed")
                {
                    wazuhInstalled = true;
                }

                if (!wazuhInstalled)
                {
                    _logger.Info("Wazuh is not installed, installing...");
                    return await InstallWazuh();
                }

                _logger.Info("Wazuh is already installed, checking if services are running");

                // Start all found Wazuh services
                bool servicesStarted = await StartWazuhServices();

                if (!servicesStarted)
                {
                    _logger.Warning("Failed to start any Wazuh services");
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.Error($"Error updating Wazuh: {ex.Message}", ex);
                return false;
            }
        }
        private List<string> FindWazuhServices()
        {
            var wazuhServices = new List<string>();

            try
            {
                _logger.Info("Searching for Wazuh services dynamically...");

                // Use PowerShell to find Wazuh-related services - FIXED SYNTAX
                string script = @"
            Get-WmiObject -Class Win32_Service | Where-Object {
                $_.Name -like '*wazuh*' -or 
                $_.DisplayName -like '*wazuh*' -or 
                $_.PathName -like '*wazuh*'
            } | ForEach-Object { 
                Write-Output ""$($_.Name)|$($_.DisplayName)|$($_.State)""
            }
        ";

                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "powershell.exe",
                        Arguments = $"-Command \"{script}\"",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();
                process.WaitForExit();

                if (!string.IsNullOrEmpty(output))
                {
                    var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                    foreach (var line in lines)
                    {
                        var parts = line.Split('|');
                        if (parts.Length >= 1 && !string.IsNullOrEmpty(parts[0]))
                        {
                            wazuhServices.Add(parts[0].Trim());
                            _logger.Info($"Found Wazuh service: {parts[0]} ({(parts.Length > 1 ? parts[1] : "N/A")})");
                        }
                    }
                }

                if (!string.IsNullOrEmpty(error))
                {
                    _logger.Warning($"PowerShell error during Wazuh service search: {error}");
                }

                // Fallback to known patterns if nothing found
                if (wazuhServices.Count == 0)
                {
                    _logger.Info("No services found via PowerShell, trying known patterns...");
                    var knownPatterns = new[] { "Wazuh", "wazuh-agent", "WazuhSvc", "wazuh_agent", "WazuhAgent", "OssecSvc" };
                    foreach (var pattern in knownPatterns)
                    {
                        if (IsServiceInstalled(pattern))
                        {
                            wazuhServices.Add(pattern);
                            _logger.Info($"Found Wazuh service via pattern matching: {pattern}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.Error($"Error finding Wazuh services: {ex.Message}", ex);

                // Final fallback to hardcoded list
                var fallbackServices = new[] { "Wazuh", "wazuh-agent", "WazuhSvc", "OssecSvc" };
                foreach (var service in fallbackServices)
                {
                    if (IsServiceInstalled(service))
                    {
                        wazuhServices.Add(service);
                    }
                }
            }

            _logger.Info($"Total Wazuh services found: {wazuhServices.Count}");
            return wazuhServices.Distinct().ToList();
        }

        private List<string> GetWazuhDirectories()
        {
            var directories = new List<string>
            {
                @"C:\Program Files\Wazuh",
                @"C:\Program Files\Wazuh Agent",
                @"C:\Program Files (x86)\Wazuh",
                @"C:\Program Files (x86)\Wazuh Agent"
            };

            return directories.Where(Directory.Exists).ToList();
        }

        private async Task<bool> StartWazuhServices()
        {
            var wazuhServices = FindWazuhServices();

            if (wazuhServices.Count == 0)
            {
                _logger.Warning("No Wazuh services found to start");
                return false;
            }

            bool anyStarted = false;
            foreach (var serviceName in wazuhServices)
            {
                try
                {
                    _logger.Info($"Attempting to start Wazuh service: {serviceName}");

                    using (var service = new ServiceController(serviceName))
                    {
                        service.Refresh();

                        if (service.Status == ServiceControllerStatus.Running)
                        {
                            _logger.Info($"Wazuh service {serviceName} is already running");
                            anyStarted = true;
                            continue;
                        }

                        if (service.Status == ServiceControllerStatus.Stopped)
                        {
                            service.Start();
                            await Task.Run(() => service.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30)));
                            _logger.Info($"Successfully started Wazuh service: {serviceName}");
                            anyStarted = true;
                        }
                        else
                        {
                            _logger.Warning($"Wazuh service {serviceName} is in {service.Status} state");
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.Error($"Error starting Wazuh service {serviceName}: {ex.Message}", ex);

                    // Try alternative method using net start
                    try
                    {
                        _logger.Info($"Trying to start {serviceName} with net start command");
                        var process = Process.Start(new ProcessStartInfo
                        {
                            FileName = "net",
                            Arguments = $"start \"{serviceName}\"",
                            UseShellExecute = true,
                            Verb = "runas",
                            CreateNoWindow = true,
                            WindowStyle = ProcessWindowStyle.Hidden
                        });

                        if (process != null)
                        {
                            process.WaitForExit();
                            if (process.ExitCode == 0)
                            {
                                _logger.Info($"Successfully started {serviceName} with net start");
                                anyStarted = true;
                            }
                        }
                    }
                    catch (Exception netEx)
                    {
                        _logger.Error($"Failed to start {serviceName} with net start: {netEx.Message}");
                    }
                }
            }

            return anyStarted;
        }
        private void DebugListAllServices()
        {
            try
            {
                _logger.Info("=== DEBUG: Listing all services containing 'wazuh' ===");

                var services = ServiceController.GetServices();
                var wazuhServices = services.Where(s =>
                    s.ServiceName.ToLower().Contains("wazuh") ||
                    s.DisplayName.ToLower().Contains("wazuh")
                ).ToList();

                if (wazuhServices.Any())
                {
                    foreach (var service in wazuhServices)
                    {
                        _logger.Info($"Found service: Name='{service.ServiceName}', DisplayName='{service.DisplayName}', Status={service.Status}");
                    }
                }
                else
                {
                    _logger.Info("No Wazuh-related services found in system");
                }

                _logger.Info("=== END DEBUG SERVICE LIST ===");
            }
            catch (Exception ex)
            {
                _logger.Error($"Error listing services: {ex.Message}", ex);
            }
        }
        private async Task<bool> InstallWazuh()
        {
            try
            {
                _logger.Info("Installing Wazuh");

                // Download Wazuh PowerShell script
                string scriptUrl = GetComponentUrl("Wazuh.ps1");
                string scriptPath = Path.Combine(_config.TempPath, "Wazuh.ps1");

                var response = await _httpClient.GetAsync(scriptUrl);
                if (!response.IsSuccessStatusCode)
                {
                    _logger.Warning($"Failed to download Wazuh installation script. Status code: {response.StatusCode}");
                    return false;
                }

                using (var fileStream = new FileStream(scriptPath, FileMode.Create, FileAccess.Write))
                {
                    await response.Content.CopyToAsync(fileStream);
                }

                _logger.Info($"Downloaded Wazuh installation script to {scriptPath}");

                // Check if Wazuh Groups were specified
                string modifiedScriptPath = scriptPath;

                if (!string.IsNullOrEmpty(_config.WazuhGroups))
                {
                    _logger.Info($"Adding Wazuh Groups to installation: {_config.WazuhGroups}");

                    // Read the original PowerShell script
                    string scriptContent = File.ReadAllText(scriptPath);

                    // Look for the main command line in the script
                    // Based on the script from document #6, we need to add the WAZUH_AGENT_GROUP parameter
                    // to the msiexec command

                    if (scriptContent.Contains("msiexec.exe"))
                    {
                        // Add the WAZUH_AGENT_GROUP parameter to the msiexec command
                        scriptContent = scriptContent.Replace(
                            "msiexec.exe /i $env:tmp\\wazuh-agent /q WAZUH_MANAGER='soc.novasky.io'",
                            $"msiexec.exe /i $env:tmp\\wazuh-agent /q WAZUH_MANAGER='soc.novasky.io' WAZUH_AGENT_GROUP='{_config.WazuhGroups}'");

                        // Save the modified script for debugging
                        modifiedScriptPath = Path.Combine(_config.TempPath, "Wazuh_Modified.ps1");
                        File.WriteAllText(modifiedScriptPath, scriptContent);

                        _logger.Info($"Created modified Wazuh script with group parameter at: {modifiedScriptPath}");
                    }
                    else
                    {
                        // Save the script for review if we couldn't identify where to modify it
                        string debugScriptPath = Path.Combine(_config.TempPath, "Wazuh_Debug.ps1");
                        File.WriteAllText(debugScriptPath, scriptContent);
                        _logger.Warning($"Could not identify where to insert Wazuh group parameter - saved script for debugging at: {debugScriptPath}");
                    }
                }

                // Execute PowerShell script to install Wazuh
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "powershell.exe",
                        Arguments = $"-ExecutionPolicy Bypass -File \"{modifiedScriptPath}\"",
                        CreateNoWindow = false,
                        UseShellExecute = true,
                        Verb = "runas",
                        RedirectStandardOutput = false,
                        RedirectStandardError = false
                    }
                };

                process.Start();
                await Task.Run(() => process.WaitForExit());

                // Give the installation some time to complete registration of the service
                _logger.Info("Wazuh installation completed, checking for services...");
                await Task.Delay(10000); // Increased to 10 seconds

                // Add debug service listing
                DebugListAllServices();

                // Try multiple attempts to find the service with delays
                string serviceName = null;
                for (int attempt = 1; attempt <= 3; attempt++)
                {
                    _logger.Info($"Attempting to find Wazuh service (attempt {attempt}/3)...");

                    foreach (string possibleName in new[] { "Wazuh", "wazuh-agent", "WazuhSvc", "OssecSvc" })
                    {
                        if (IsServiceInstalled(possibleName))
                        {
                            serviceName = possibleName;
                            _logger.Info($"Found Wazuh service: {serviceName}");
                            break;
                        }
                    }

                    if (!string.IsNullOrEmpty(serviceName))
                        break;

                    if (attempt < 3)
                    {
                        _logger.Info("No Wazuh service found yet, waiting 5 more seconds...");
                        await Task.Delay(5000);
                    }
                }

                if (!string.IsNullOrEmpty(serviceName))
                {
                    // Start Wazuh service
                    _logger.Info($"Starting Wazuh service ({serviceName})...");
                    bool started = await StartService(serviceName);

                    if (!started)
                    {
                        // Try alternative method via net start
                        _logger.Info("Attempting to start Wazuh service with net start command...");
                        try
                        {
                            Process netProcess = Process.Start(new ProcessStartInfo
                            {
                                FileName = "net",
                                Arguments = $"start {serviceName}",
                                UseShellExecute = true,
                                Verb = "runas",
                                CreateNoWindow = false
                            });
                            netProcess.WaitForExit();

                            if (netProcess.ExitCode == 0)
                            {
                                _logger.Info("Successfully started Wazuh service with net start command");
                            }
                            else
                            {
                                _logger.Warning($"Failed to start Wazuh service with net start command. Exit code: {netProcess.ExitCode}");
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.Error($"Error executing net start command: {ex.Message}", ex);
                        }
                    }
                }
                else
                {
                    _logger.Warning("Could not determine Wazuh service name after installation");

                    // Try possible service names as fallback
                    await TryStartService("Wazuh");
                    await TryStartService("wazuh-agent");
                    await TryStartService("WazuhSvc");
                }

                // Clean up all script files
                try
                {
                    // Delete the original script file
                    if (File.Exists(scriptPath))
                    {
                        File.Delete(scriptPath);
                    }

                    // Delete the modified script file if it exists and is different from the original
                    if (modifiedScriptPath != scriptPath && File.Exists(modifiedScriptPath))
                    {
                        File.Delete(modifiedScriptPath);
                        _logger.Info("Removed all temporary Wazuh installation scripts");
                    }

                    // Clean up any debug script file that might have been created
                    string debugScriptPath = Path.Combine(_config.TempPath, "Wazuh_Debug.ps1");
                    if (File.Exists(debugScriptPath))
                    {
                        File.Delete(debugScriptPath);
                    }
                }
                catch (Exception ex)
                {
                    // Just log the error but continue - not cleaning up temp files isn't critical
                    _logger.Warning($"Error cleaning up temporary script files: {ex.Message}");
                }
                // Set a version marker to prevent constant reinstallation
                _config.UpdateComponentVersion("Wazuh", "installed");

                _logger.Info("Wazuh installed successfully");
                return true;
            }
            catch (Exception ex)
            {
                _logger.Error($"Error installing Wazuh: {ex.Message}", ex);
                return false;
            }
        }

        private bool IsServiceInstalled(string serviceName)
        {
            try
            {
                using (var service = new ServiceController(serviceName))
                {
                    // Actually try to access the service properties to verify it exists
                    service.Refresh();
                    var status = service.Status; // This will throw if service doesn't exist
                    var displayName = service.DisplayName; // Additional verification
                    _logger.Info($"Service {serviceName} exists with status: {status}");
                    return true;
                }
            }
            catch (Exception ex)
            {
                _logger.Info($"Service {serviceName} does not exist: {ex.Message}");
                return false;
            }
        }

        // Helper methods for Wazuh service management
        private string GetWazuhServiceName()
        {
            // Try the various possible service names for Wazuh
            string[] possibleNames = { "Wazuh", "wazuh-agent", "WazuhSvc" };

            foreach (string name in possibleNames)
            {
                if (IsServiceInstalled(name))
                {
                    return name;
                }
            }

            return null;
        }

        private bool IsProductInstalled(string productName)
        {
            try
            {
                // Check for product in registry
                string uninstallKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
                using (var baseKey = Registry.LocalMachine.OpenSubKey(uninstallKey))
                {
                    if (baseKey != null)
                    {
                        foreach (string subKeyName in baseKey.GetSubKeyNames())
                        {
                            using (var subKey = baseKey.OpenSubKey(subKeyName))
                            {
                                string displayName = subKey.GetValue("DisplayName") as string;
                                if (!string.IsNullOrEmpty(displayName) && displayName.IndexOf(productName, StringComparison.OrdinalIgnoreCase) >= 0)
                                {
                                    return true;
                                }
                            }
                        }
                    }
                }

                // Also check 32-bit registry on 64-bit systems
                string uninstallKey32 = @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall";
                using (var baseKey = Registry.LocalMachine.OpenSubKey(uninstallKey32))
                {
                    if (baseKey != null)
                    {
                        foreach (string subKeyName in baseKey.GetSubKeyNames())
                        {
                            using (var subKey = baseKey.OpenSubKey(subKeyName))
                            {
                                string displayName = subKey.GetValue("DisplayName") as string;
                                if (!string.IsNullOrEmpty(displayName) && displayName.IndexOf(productName, StringComparison.OrdinalIgnoreCase) >= 0)
                                {
                                    return true;
                                }
                            }
                        }
                    }
                }

                // Also check Program Files for Wazuh folders
                string[] possiblePaths = {
            @"C:\Program Files\Wazuh",
            @"C:\Program Files\Wazuh Agent",
            @"C:\Program Files (x86)\Wazuh",
            @"C:\Program Files (x86)\Wazuh Agent"
        };

                foreach (string path in possiblePaths)
                {
                    if (Directory.Exists(path))
                    {
                        return true;
                    }
                }

                return false;
            }
            catch (Exception ex)
            {
                _logger.Error($"Error checking if product is installed: {ex.Message}", ex);
                return false;
            }
        }

        private async Task<bool> TryStartService(string serviceName)
        {
            try
            {
                try
                {
                    // Check if service exists
                    using (var service = new ServiceController(serviceName))
                    {
                        _logger.Info($"Found Wazuh service with name: {serviceName}, attempting to start");
                        return await StartService(serviceName);
                    }
                }
                catch
                {
                    // Service does not exist
                    return false;
                }
            }
            catch (Exception ex)
            {
                _logger.Warning($"Error trying to start service {serviceName}: {ex.Message}");
                return false;
            }
        }

        private async Task<bool> StopService(string serviceName)
        {
            try
            {
                var service = new ServiceController(serviceName);

                if (service.Status != ServiceControllerStatus.Stopped && service.Status != ServiceControllerStatus.StopPending)
                {
                    _logger.Info($"Stopping {serviceName} service");
                    service.Stop();
                    await Task.Run(() => service.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30)));
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.Error($"Error stopping {serviceName} service: {ex.Message}", ex);
                return false;
            }
        }

        private async Task<bool> StartService(string serviceName)
        {
            try
            {
                _logger.Info($"Attempting to start service: {serviceName}");

                // First verify the service actually exists
                if (!IsServiceInstalled(serviceName))
                {
                    _logger.Warning($"Cannot start {serviceName} - service does not exist");
                    return false;
                }

                using (var service = new ServiceController(serviceName))
                {
                    service.Refresh();
                    _logger.Info($"Current {serviceName} status: {service.Status}");

                    if (service.Status == ServiceControllerStatus.Running)
                    {
                        _logger.Info($"Service {serviceName} is already running");
                        return true;
                    }

                    if (service.Status == ServiceControllerStatus.Stopped)
                    {
                        _logger.Info($"Starting {serviceName} service...");
                        service.Start();

                        // Wait for the service to start with multiple verification attempts
                        for (int i = 0; i < 6; i++) // 6 attempts = 30 seconds max wait
                        {
                            await Task.Delay(5000); // Wait 5 seconds between checks
                            service.Refresh();

                            _logger.Info($"Service {serviceName} status after {(i + 1) * 5} seconds: {service.Status}");

                            if (service.Status == ServiceControllerStatus.Running)
                            {
                                _logger.Info($"Successfully started {serviceName} service");
                                return true;
                            }

                            if (service.Status == ServiceControllerStatus.StartPending)
                            {
                                _logger.Info($"Service {serviceName} is still starting, waiting...");
                                continue;
                            }

                            // If it's stopped or failed, something went wrong
                            if (service.Status == ServiceControllerStatus.Stopped)
                            {
                                _logger.Warning($"Service {serviceName} stopped unexpectedly during startup");
                                break;
                            }
                        }

                        // Final status check
                        service.Refresh();
                        if (service.Status == ServiceControllerStatus.Running)
                        {
                            _logger.Info($"Service {serviceName} is now running");
                            return true;
                        }
                        else
                        {
                            _logger.Error($"Failed to start {serviceName}. Final status: {service.Status}");
                            return false;
                        }
                    }
                    else
                    {
                        _logger.Warning($"Service {serviceName} is in {service.Status} state, cannot start");
                        return false;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.Error($"Error starting {serviceName} service: {ex.Message}", ex);
                return false;
            }
        }

        private async Task<bool> RestartService(string serviceName)
        {
            await StopService(serviceName);
            return await StartService(serviceName);
        }

        private string GetComponentUrl(string fileName)
        {
            // Construct client-specific URL using the client ID
            return $"{_config.ServerUrl}{_config.ClientId}/{fileName}";
        }
    }

    public class StatusReporter
    {
        private readonly HttpClient _httpClient;
        private readonly Logger _logger;
        private readonly ConfigManager _config;

        public StatusReporter(HttpClient httpClient, Logger logger, ConfigManager config)
        {
            _httpClient = httpClient;
            _logger = logger;
            _config = config;
        }

        public async Task<bool> ReportStatus(string status)
        {
            try
            {
                // Create status report
                var statusReport = new
                {
                    eventType = "AgentStatus",
                    clientId = _config.ClientId,
                    computerName = Environment.MachineName,
                    status = status,
                    timestamp = DateTime.Now.ToString("o"),
                    agentVersion = _config.AgentVersion,
                    components = await CheckComponentStatus(),
                    osVersion = Environment.OSVersion.VersionString
                };

                // Send to server
                string statusUrl = $"{_config.ServerUrl}api/telemetry";
                var jsonContent = new StringContent(
                    JsonSerializer.Serialize(statusReport),
                    Encoding.UTF8,
                    "application/json"
                );

                var response = await _httpClient.PostAsync(statusUrl, jsonContent);
                if (!response.IsSuccessStatusCode)
                {
                    _logger.Warning($"Failed to report status. Status code: {response.StatusCode}");
                    return false;
                }

                _logger.Info($"Status reported successfully: {status}");
                return true;
            }
            catch (Exception ex)
            {
                _logger.Error($"Error reporting status: {ex.Message}", ex);
                return false;
            }
        }

        public async Task<Dictionary<string, string>> CheckComponentStatus()
        {
            var status = new Dictionary<string, string>();

            try
            {
                // Check Fibratus
                status["Fibratus"] = await GetServiceStatus("Fibratus");

                // Check Velociraptor
                status["Velociraptor"] = await GetServiceStatus("Velociraptor");

                // Check Wazuh if installed - use direct service checks
                bool wazuhFound = false;
                foreach (string serviceName in new[] { "Wazuh", "wazuh-agent", "WazuhSvc" })
                {
                    try
                    {
                        using (var service = new ServiceController(serviceName))
                        {
                            // If we get here, the service exists
                            status["Wazuh"] = service.Status.ToString();
                            wazuhFound = true;
                            break;
                        }
                    }
                    catch
                    {
                        // Service not found, try next name
                    }
                }

                // If no service found, check if Wazuh is installed in other ways
                if (!wazuhFound)
                {
                    // Check program files directories
                    string[] possiblePaths = {
                @"C:\Program Files\Wazuh",
                @"C:\Program Files\Wazuh Agent",
                @"C:\Program Files (x86)\Wazuh",
                @"C:\Program Files (x86)\Wazuh Agent"
            };

                    foreach (string path in possiblePaths)
                    {
                        if (Directory.Exists(path))
                        {
                            status["Wazuh"] = "Unknown";
                            break;
                        }
                    }
                }

                if (!wazuhFound)
                {
                    status["Wazuh"] = "NotInstalled";
                }

                return status;
            }
            catch (Exception ex)
            {
                _logger.Error($"Error checking component status: {ex.Message}", ex);
                return status;
            }
        }

        public async Task<Dictionary<string, object>> CollectStatusInfo()
        {
            var statusInfo = new Dictionary<string, object>();

            try
            {
                // Basic system info
                statusInfo["ComputerName"] = Environment.MachineName;
                statusInfo["OSVersion"] = Environment.OSVersion.VersionString;
                statusInfo["AgentVersion"] = _config.AgentVersion;
                statusInfo["ClientId"] = _config.ClientId;
                statusInfo["Timestamp"] = DateTime.Now.ToString("o");

                // Component versions
                statusInfo["ComponentVersions"] = _config.ComponentVersions;

                // Component status
                statusInfo["ComponentStatus"] = await CheckComponentStatus();

                // Additional system info
                statusInfo["ProcessorCount"] = Environment.ProcessorCount;
                statusInfo["SystemDirectory"] = Environment.SystemDirectory;
                statusInfo["UserDomainName"] = Environment.UserDomainName;
                statusInfo["UserName"] = Environment.UserName;

                // Network info
                try
                {
                    var ipAddresses = System.Net.Dns.GetHostAddresses(Environment.MachineName)
                        .Where(ip => ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        .Select(ip => ip.ToString())
                        .ToArray();

                    statusInfo["IPAddresses"] = ipAddresses;
                }
                catch
                {
                    statusInfo["IPAddresses"] = new string[0];
                }

                return statusInfo;
            }
            catch (Exception ex)
            {
                _logger.Error($"Error collecting status info: {ex.Message}", ex);
                statusInfo["Error"] = ex.Message;
                return statusInfo;
            }
        }

        private async Task<string> GetServiceStatus(string serviceName)
        {
            try
            {
                var service = new ServiceController(serviceName);
                return service.Status.ToString();
            }
            catch
            {
                return "NotInstalled";
            }
        }
    }
}
#endregion
