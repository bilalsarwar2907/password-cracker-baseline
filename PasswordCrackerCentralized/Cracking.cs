using PasswordCrackerCentralized.model;
using PasswordCrackerCentralized.util;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace PasswordCrackerCentralized
{
    public class Cracking
    {
        /// <summary>
        /// The algorithm used for encryption.
        /// Must be exactly the same algorithm that was used to encrypt the passwords in the password file
        /// </summary>
        private readonly HashAlgorithm _messageDigest;

        public Cracking()
        {
            _messageDigest = new SHA1CryptoServiceProvider();
            //_messageDigest = new MD5CryptoServiceProvider();
            // seems to be same speed
        }

        /// <summary>
        /// Runs the password cracking algorithm
        /// </summary>
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //public void RunCracking()
        //{
        //    Stopwatch stopwatch = Stopwatch.StartNew();

        //    List<UserInfo> userInfos =
        //        PasswordFileHandler.ReadPasswordFile("passwords.txt");
        //    Console.WriteLine("passwd opeend");

        //    List<UserInfoClearText> result = new List<UserInfoClearText>();

        //    using (FileStream fs = new FileStream("webster-dictionary.txt", FileMode.Open, FileAccess.Read))

        //    using (StreamReader dictionary = new StreamReader(fs))
                      
        //    {

        //        while (!dictionary.EndOfStream)
        //        {
                   
        //            String dictionaryEntry = dictionary.ReadLine();
        //            IEnumerable<UserInfoClearText> partialResult = CheckWordWithVariations(dictionaryEntry, userInfos);
        //            result.AddRange(partialResult);
        //        }
        //    }
        //    stopwatch.Stop();
        //    Console.WriteLine(string.Join(", ", result));
        //    Console.WriteLine("Out of {0} password {1} was found ", userInfos.Count, result.Count);
        //    Console.WriteLine();
        //    Console.WriteLine("Time elapsed: {0}", stopwatch.Elapsed);
        //}
        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


    public void RunCracking()
    {
        Stopwatch stopwatch = Stopwatch.StartNew();

        List<UserInfo> userInfos = PasswordFileHandler.ReadPasswordFile("passwords.txt");
        Console.WriteLine("passwd opened");

        // 1. Thread-safe collection for multiple cores
        ConcurrentBag<UserInfoClearText> result = new ConcurrentBag<UserInfoClearText>();

        // 2. Load the dictionary all at once (just like you wrote!)
        List<string> dictionary = File.ReadAllLines("webster-dictionary.txt").ToList();

        // 3. Process chunks in parallel using all CPU cores
        Parallel.ForEach(dictionary, dictionaryEntry =>
        {
            IEnumerable<UserInfoClearText> partialResult = CheckWordWithVariations(dictionaryEntry, userInfos);

            foreach (var item in partialResult)
            {
                result.Add(item);
            }
        });

        stopwatch.Stop();

        Console.WriteLine(string.Join(", ", result));
        Console.WriteLine("Out of {0} passwords, {1} were found", userInfos.Count, result.Count);
        Console.WriteLine();
        Console.WriteLine("Time elapsed: {0}", stopwatch.Elapsed);
    }




    /// <summary>
    /// Generates a lot of variations, encrypts each of the and compares it to all entries in the password file
    /// </summary>
    /// <param name="dictionaryEntry">A single word from the dictionary</param>
    /// <param name="userInfos">List of (username, encrypted password) pairs from the password file</param>
    /// <returns>A list of (username, readable password) pairs. The list might be empty</returns>
    private IEnumerable<UserInfoClearText> CheckWordWithVariations(String dictionaryEntry, List<UserInfo> userInfos)
        {
            List<UserInfoClearText> result = new List<UserInfoClearText>(); //might be empty

            String possiblePassword = dictionaryEntry;
            IEnumerable<UserInfoClearText> partialResult = CheckSingleWord(userInfos, possiblePassword);
            result.AddRange(partialResult);

            String possiblePasswordUpperCase = dictionaryEntry.ToUpper();
            IEnumerable<UserInfoClearText> partialResultUpperCase = CheckSingleWord(userInfos, possiblePasswordUpperCase);
            result.AddRange(partialResultUpperCase);

            String possiblePasswordCapitalized = StringUtilities.Capitalize(dictionaryEntry);
            IEnumerable<UserInfoClearText> partialResultCapitalized = CheckSingleWord(userInfos, possiblePasswordCapitalized);
            result.AddRange(partialResultCapitalized);

            String possiblePasswordReverse = StringUtilities.Reverse(dictionaryEntry);
            IEnumerable<UserInfoClearText> partialResultReverse = CheckSingleWord(userInfos, possiblePasswordReverse);
            result.AddRange(partialResultReverse);

            for (int i = 0; i < 100; i++)
            {
                String possiblePasswordEndDigit = dictionaryEntry + i;
                IEnumerable<UserInfoClearText> partialResultEndDigit = CheckSingleWord(userInfos, possiblePasswordEndDigit);
                result.AddRange(partialResultEndDigit);
            }

            for (int i = 0; i < 100; i++)
            {
                String possiblePasswordStartDigit = i + dictionaryEntry;
                IEnumerable<UserInfoClearText> partialResultStartDigit = CheckSingleWord(userInfos, possiblePasswordStartDigit);
                result.AddRange(partialResultStartDigit);
            }

            for (int i = 0; i < 10; i++)
            {
                for (int j = 0; j < 10; j++)
                {
                    String possiblePasswordStartEndDigit = i + dictionaryEntry + j;
                    IEnumerable<UserInfoClearText> partialResultStartEndDigit = CheckSingleWord(userInfos, possiblePasswordStartEndDigit);
                    result.AddRange(partialResultStartEndDigit);
                }
            }

            return result;
        }

        /// <summary>
        /// Checks a single word (or rather a variation of a word): Encrypts and compares to all entries in the password file
        /// </summary>
        /// <param name="userInfos"></param>
        /// <param name="possiblePassword">List of (username, encrypted password) pairs from the password file</param>
        /// <returns>A list of (username, readable password) pairs. The list might be empty</returns>
        private IEnumerable<UserInfoClearText> CheckSingleWord(IEnumerable<UserInfo> userInfos, String possiblePassword)
        {
            char[] charArray = possiblePassword.ToCharArray();
            byte[] passwordAsBytes = Array.ConvertAll(charArray, PasswordFileHandler.GetConverter());

            //byte[] encryptedPassword = _messageDigest.ComputeHash(passwordAsBytes);
            //string encryptedPasswordBase64 = System.Convert.ToBase64String(encryptedPassword);
            ///////////////////////////////////////////////////////////////////////////////////////
            byte[] encryptedPassword;
            using (SHA1CryptoServiceProvider sha1 = new SHA1CryptoServiceProvider())
            {
                encryptedPassword = sha1.ComputeHash(passwordAsBytes);
            }

            List<UserInfoClearText> results = new List<UserInfoClearText>();

            foreach (UserInfo userInfo in userInfos)
            {
                if (CompareBytes(userInfo.EntryptedPassword, encryptedPassword))  //compares byte arrays
                {
                    results.Add(new UserInfoClearText(userInfo.Username, possiblePassword));
                    Console.WriteLine(userInfo.Username + " " + possiblePassword);
                }
            }
            return results;
        }

        /// <summary>
        /// Compares to byte arrays. Encrypted words are byte arrays
        /// </summary>
        /// <param name="firstArray"></param>
        /// <param name="secondArray"></param>
        /// <returns></returns>
        private static bool CompareBytes(IList<byte> firstArray, IList<byte> secondArray)
        {
            //if (secondArray == null)
            //{
            //    throw new ArgumentNullException("firstArray");
            //}
            //if (secondArray == null)
            //{
            //    throw new ArgumentNullException("secondArray");
            //}
            if (firstArray.Count != secondArray.Count)
            {
                return false;
            }
            for (int i = 0; i < firstArray.Count; i++)
            {
                if (firstArray[i] != secondArray[i])
                    return false;
            }
            return true;
        }

    }
}
