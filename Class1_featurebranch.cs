using System;
using System.IO;
using System.Diagnostics;
using System.Data.SqlClient;
using System.Security.Cryptography;
using System.Text;

namespace SampleCodeNet8
{
    public class Class1
    {
        // SAST Vulnerability: Hardcoded credentials
        private string password = "P@ssw0rd123!";
        private const string ApiKey = "sk-1234567890abcdef";
        private string password2 = "admin123";
        private string newkey = "secretkey123";
        private string secret = "P@ssw0rd123!";
        private string connectionString = "Server=localhost;Database=TestDB;User Id=sa;Password=Password123!;";
        private string jwtSecret = "my-secret-jwt-key-123";
        private string newsecret = "Kishore@123456";

        // SAST Vulnerability: Path Traversal - CWE-22
        public string ReadFile(string fileName)
        {
            // Vulnerable: Direct concatenation allows directory traversal
            string filePath = "C:\\temp\\" + fileName;
            return File.ReadAllText(filePath);
        }

        // SAST Vulnerability: Directory Traversal - CWE-22  
        public string ReadUserFile(string userPath)
        {
            // Vulnerable: No validation of user-provided path
            return File.ReadAllText(userPath);
        }

        // SAST Vulnerability: Cross-Site Scripting - CWE-79
        public string DisplayUserInput(string userInput)
        {
            // Vulnerable: User input directly embedded in HTML without escaping
            return "<div>Hello " + userInput + "</div>";
        }

        // SAST Vulnerability: HTML Injection - CWE-79
        public string RenderHtml(string content)
        {
            // Vulnerable: Direct HTML injection from user content
            return $"<html><body>{content}</body></html>";
        }

        private static int counter = 0;
        public void IncrementCounter()
        {
            counter = counter + 1;
        }

        // SAST Vulnerability: Weak Random Number Generation
        public string GenerateToken()
        {
            Random random = new Random(); // Weak random for security purposes
            return random.Next().ToString();
        }

        // SAST Vulnerability: SQL Injection - CWE-89
        public string GetUserData(string userId)
        {
            // Vulnerable: Direct user input concatenation in SQL query
            string query = "SELECT * FROM Users WHERE Id = '" + userId + "'";
            using (SqlConnection conn = new SqlConnection(connectionString))
            {
                SqlCommand cmd = new SqlCommand(query, conn);
                conn.Open();
                var result = cmd.ExecuteScalar();
                return result?.ToString() ?? "Not found";
            }
        }

        // SAST Vulnerability: SQL Injection - Alternative pattern
        public void DeleteUser(string username)
        {
            string sql = $"DELETE FROM Users WHERE username = '{username}'";
            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                connection.Open();
                SqlCommand command = new SqlCommand(sql, connection);
                command.ExecuteNonQuery();
            }
        }

        // SAST Vulnerability: Weak Cryptography
        public string WeakEncrypt(string plainText)
        {
            MD5 md5 = MD5.Create(); // Weak hashing algorithm
            byte[] hash = md5.ComputeHash(Encoding.UTF8.GetBytes(plainText));
            return Convert.ToBase64String(hash);
        }

        // SAST Vulnerability: Command Injection - CWE-78
        public string PingHost(string host)
        {
            try
            {
                // Direct user input to system command - vulnerable to injection
                var process = new Process();
                process.StartInfo.FileName = "cmd";
                process.StartInfo.Arguments = "/c ping " + host;
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.Start();
                
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();
                return output;
            }
            catch (Exception ex)
            {
                return $"Error: {ex.Message}";
            }
        }

        // SAST Vulnerability: OS Command Injection - CWE-78
        public string ExecuteCommand(string command)
        {
            // Direct execution of user input as system command
            var startInfo = new ProcessStartInfo("cmd.exe", "/c " + command);
            var process = Process.Start(startInfo);
            return "Command executed";
        }

        // SAST Vulnerability: Path Traversal - CWE-22
        public string ReadConfigFile(string filename)
        {
            // Direct user input used in file path construction
            var path = Path.Combine("C:\\config\\", filename);
            return System.IO.File.ReadAllText(path);
        }
    }
}
