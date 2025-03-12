using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using DidiSoft.Pgp;
using System.Security.Principal;
using System.IO;

// 用户类，用于管理当前登录用户的信息和授权操作
public class User
{
    private string username; // 用户名
    private SecurityIdentifier sid; // 用户安全标识符
    private string userID; // 用户ID
    private string[] allAuthorizedUsers; // 所有已授权用户
    private string[] allAuthorizedUsersPublicKey; // 所有已授权用户的公钥路径

    // 构造函数，初始化用户信息
    public User()
    {
        username = Environment.UserName;
        WindowsIdentity windowsIdentity = WindowsIdentity.GetCurrent();
        sid = windowsIdentity.User;
        userID = GetUserID();
        Console.WriteLine("当前用户信息");
        Console.WriteLine("-----------------------------------------------------------------------------------------------------------");
        Console.WriteLine($"当前活动用户名为：{username}\n安全标识符为：{sid}\n当前userID为：{userID}");
        Console.WriteLine("-----------------------------------------------------------------------------------------------------------\n");
    }

    // 获取用户名
    public string get_username()
    {
        return username;
    }

    // 获取用户安全标识符
    public SecurityIdentifier get_sid()
    {
        return sid;
    }

    // 获取用户ID
    public string GetUserID()
    {
        PGPLib pgp = new PGPLib();
        pgp.Hash = HashAlgorithm.MD5;
        userID = sid.GetHashCode().ToString();
        return userID;
    }

    // 获取所有已授权用户
    public string[] get_all_Authorized_Users()
    {
        return allAuthorizedUsers;
    }

    // 获取所有已授权用户的公钥路径
    public string[] get_all_Authorized_Uers_PublicKey()
    {
        return allAuthorizedUsersPublicKey;
    }

    // 设置能够访问到的所有已授权用户的公钥路径
    public void User_Authorization()
    {
        string[] allUsersPath = Directory.GetDirectories(Global.pathString); // 获取用户文件夹路径

        if (allUsersPath.Length == 1)
        {
            Console.WriteLine("目前该文件系统未检测到其他用户");
        }

        List<string> userList = new List<string> { Environment.UserName };
        List<string> publicKeyList = new List<string> { Path.Combine(Global.pathStringKey, "public_key_exported.asc") };

        foreach (string userPath in allUsersPath)
        {
            string name = Path.GetFileName(userPath);
            string publicKey = Path.Combine(Global.pathString, name, Global.folderName1, "public_key_exported.asc"); // 用户公钥文件路径
            if (name != Environment.UserName && File.Exists(publicKey))
            {
                Console.WriteLine("检测到用户{0}", name);
                Console.WriteLine("您是否要为用户{0}开放该文件的调阅权限？（Y/N）", name);
                string answer = Console.ReadLine();
                while (true)
                {
                    if ((answer == "Y") || (answer == "y"))
                    {
                        userList.Add(name);
                        publicKeyList.Add(publicKey);
                        Console.WriteLine("为用户{0}开放该文件的调阅权限成功", name);
                        break;
                    }
                    else if ((answer == "N") || (answer == "n"))
                    {
                        Console.WriteLine("为用户{0}开放该文件的调阅权限失败", name);
                        break;
                    }
                    else
                    {
                        Console.WriteLine("请正确输入！");
                        answer = Console.ReadLine();
                    }
                }

            }
        }
        allAuthorizedUsers = userList.ToArray();
        allAuthorizedUsersPublicKey = publicKeyList.ToArray();
    }

    // 检测所有用户的公钥信息
    public void detect_All_User_Public_key()
    {
        List<string> userList = new List<string> { };
        List<string> publicKeyList = new List<string> { };

        string[] allUsersPath = Directory.GetDirectories(Global.pathString); // 获取用户文件夹路径
        foreach (string userPath in allUsersPath)
        {
            string name = Path.GetFileName(userPath);
            string publicKey = Path.Combine(Global.pathString, name, Global.folderName1, "public_key_exported.asc"); // 用户公钥文件路径
            if (File.Exists(publicKey))
            {
                userList.Add(name);
                publicKeyList.Add(publicKey);
            }
        }
        allAuthorizedUsers = userList.ToArray();
        allAuthorizedUsersPublicKey = publicKeyList.ToArray();
    }

    // 析构函数，保证释放敏感信息
    ~User()
    {

    }
}

// 文件位置管理类
public class Global
{
    // 文件基础路径
    public static string baseName = "D:\\";
    // 总文件夹名称
    public static string folderName = "OpenPGP_File_Manage_show";
    // 密钥文件夹名称
    public static string folderName1 = "Key";
    // 文件文件夹名称
    public static string folderName2 = "File";

    // 总文件夹路径
    public static string pathString = System.IO.Path.Combine(baseName, folderName);
    // 用户文件夹路径
    public static string pathStringUser = System.IO.Path.Combine(pathString, Environment.UserName);
    // 用户密钥文件夹路径
    public static string pathStringKey = System.IO.Path.Combine(pathStringUser, folderName1);
    // 用户文件文件夹路径
    public static string pathStringFile = System.IO.Path.Combine(pathStringUser, folderName2);

    // 构造函数，初始化文件夹信息
    public Global()
    {
        Console.WriteLine("┎--------------------------------------------┒\n");
        Console.WriteLine("│++++++++ 基于OpenPGP的文件管理系统 +++++++++│\n");
        Console.WriteLine("┖--------------------------------------------┘\n");
        SetBaseName();

        Console.WriteLine("\n应用所创建的文件夹信息");
        Console.WriteLine("-----------------------------------------------------------------------------------------------------------");
        System.IO.Directory.CreateDirectory(pathString);
        Console.WriteLine("在\"{0}\" 创建了文件夹：\"基于OpenGPG的文件系统\"的总文件夹\n", pathString);

        System.IO.Directory.CreateDirectory(pathStringUser);
        Console.WriteLine("在\"{0}\" 创建了文件夹：用户{1}的用户文件夹\n", pathStringUser, Environment.UserName);

        System.IO.Directory.CreateDirectory(pathStringKey);
        Console.WriteLine("在\"{0}\" 创建了文件夹：用户{1}的密钥（可以导出公钥）文件夹\n", pathStringKey, Environment.UserName);

        System.IO.Directory.CreateDirectory(pathStringFile);
        Console.WriteLine("在\"{0}\" 创建了文件夹：用户{1}的文件（加密、解密后的文件）的文件夹", pathStringFile, Environment.UserName);
        Console.WriteLine("-----------------------------------------------------------------------------------------------------------\n");
    }

    // 析构函数，保证释放敏感信息
    ~Global()
    {

    }

    // 设置文件基础路径
    public void SetBaseName()
    {
        Console.WriteLine("请输入项目文件夹的存放位置（默认：D:\\），输入q可跳过");
        string basename = Console.ReadLine();
        if (basename == "q")
        {
            return;
        }
        else
        {
            baseName = basename;
            // 更新文件夹路径
            pathString = System.IO.Path.Combine(baseName, folderName);
            pathStringUser = System.IO.Path.Combine(pathString, Environment.UserName);
            pathStringKey = System.IO.Path.Combine(pathStringUser, folderName1);
            pathStringFile = System.IO.Path.Combine(pathStringUser, folderName2);
        }
    }
}

public class ModeManage
{
    // 析构函数，保证释放敏感信息
    ~ModeManage()
    {

    }

    // 选择操作模式并返回相应的操作模式编号
    public int mode_input(User user)
    {
        while (true)
        {
            Console.WriteLine("原理展示请按1，存储文件请按2，调阅文件请按3");
            string mode = Console.ReadLine();
            if (mode == "1")
            {
                Console.WriteLine("\n原理展示");
                Console.WriteLine("-----------------------------------------------------------------------------------------------------------");
                Console.WriteLine("请任意输入想要加密的内容，以另起一行输入\":wq\"结束");
                return 1;
            }
            else if (mode == "2")
            {
                Console.WriteLine("\n文件存储");
                Console.WriteLine("-----------------------------------------------------------------------------------------------------------");
                Console.WriteLine("存储文件的安全模式：仅自己请按1，多用户请按2");
                while (true)
                {
                    string subMode = Console.ReadLine();
                    if (subMode == "1")
                    {
                        Console.WriteLine("该文件由用户{0}创建，并且只能由用户{0}查看", Environment.UserName);
                        Console.WriteLine("请输入文件路径");
                        return 21;
                    }
                    else if (subMode == "2")
                    {
                        user.User_Authorization();
                        Console.WriteLine("请输入文件路径");
                        return 22;
                    }
                    else
                    {
                        Console.WriteLine("请重新输入！");
                    }
                }
            }
            else if (mode == "3")
            {
                Console.WriteLine("\n文件调阅");
                Console.WriteLine("-----------------------------------------------------------------------------------------------------------");
                Console.WriteLine("请输入文件路径(后缀为.gpg)");
                return 3;
            }
            else
            {
                Console.WriteLine("请重新输入！");
            }
        }
    }

    // 根据操作模式执行相应的操作
    public void mode_control(int mode, User user, string passwd)
    {
        if (mode == 1)
        {
            // 键盘读入并签名加密字符串
            string text = "";
            string input = Console.ReadLine();
            string next = Console.ReadLine();
            while (true)
            {
                if (next == ":wq")
                {
                    text = text + input;
                    break;
                }
                else
                {
                    text = text + input + "\r\n";
                }

                input = next;
                next = Console.ReadLine();
            }

            FileManage fileManage = new FileManage();
            string afterString = fileManage.SignAndEncryptString(text, passwd, user.GetUserID());
            Console.WriteLine("\n键盘输入的字符串为:\n{0}\n\n用您的私钥先签名，再用您的公钥后加密，得到的字符串为\n{1}", text, afterString);

            fileManage.DecryptAndVerifyString(afterString, passwd, user.GetUserID());

            Console.WriteLine("-----------------------------------------------------------------------------------------------------------\n");
        }
        else if (mode == 21)
        {
            string file = Console.ReadLine();
            while (true)
            {
                if (System.IO.File.Exists(file))
                {
                    FileManage fileManage = new FileManage();
                    user.detect_All_User_Public_key();
                    string outputFile = fileManage.SignAndEncryptSinge(passwd, file, user.GetUserID());
                    bool check = fileManage.Verify(passwd, outputFile, user.get_all_Authorized_Uers_PublicKey(), user.get_all_Authorized_Users(), user.GetUserID());
                    if (!check)
                    {
                        ClearTool clearTool = new ClearTool();
                        clearTool.ClearDeletFile(outputFile);
                    }
                    else
                    {
                        Console.WriteLine("文件存储成功，并由用户\"{0}\"签名，在\"{1}\"中", Environment.UserName, outputFile);
                    }
                    Console.WriteLine("-----------------------------------------------------------------------------------------------------------\n");
                    break;
                }
                else
                {
                    Console.WriteLine("文件不存在，请重新输入文件路径");
                    file = Console.ReadLine();
                }
            }

        }
        else if (mode == 22)
        {
            string file = Console.ReadLine();
            while (true)
            {
                if (System.IO.File.Exists(file))
                {
                    FileManage fileManage = new FileManage();
                    user.detect_All_User_Public_key();
                    string outputFile = fileManage.SignAndEncryptMultiple(passwd, file, user.get_all_Authorized_Uers_PublicKey(), user.GetUserID());
                    bool check = fileManage.Verify(passwd, outputFile, user.get_all_Authorized_Uers_PublicKey(), user.get_all_Authorized_Users(), user.GetUserID());
                    if (!check)
                    {
                        ClearTool clearTool = new ClearTool();
                        clearTool.ClearDeletFile(outputFile);
                    }
                    else
                    {
                        Console.WriteLine("文件存储成功，并由用户\"{0}\"签名，在\"{1}\"中", Environment.UserName, outputFile);
                    }
                    Console.WriteLine("-----------------------------------------------------------------------------------------------------------\n");
                    break;
                }
                else
                {
                    Console.WriteLine("文件不存在，请重新输入文件路径");
                    file = Console.ReadLine();
                }
            }

        }
        else if (mode == 3)
        {
            string file = Console.ReadLine();
            while (true)
            {
                if (System.IO.File.Exists(file))
                {
                    FileManage fileManage = new FileManage();
                    user.detect_All_User_Public_key();

                    Console.WriteLine(user.get_all_Authorized_Users().Length);
                    fileManage.DecryptAndVerify(passwd, file, user.get_all_Authorized_Uers_PublicKey(), user.get_all_Authorized_Users(), user.GetUserID());
                    Console.WriteLine("-----------------------------------------------------------------------------------------------------------\n");
                    break;
                }
                else
                {
                    Console.WriteLine("文件不存在，请重新输入文件路径");
                    file = Console.ReadLine();
                }
            }
        }
    }
}


namespace OpenPGP_File_Manage
{
    class Program
    {
        // 析构函数，保证释放敏感信息
        ~Program()
        {
        }

        static void Main(string[] args)
        {
            // 展示文件夹创建
            Global global = new Global();

            // 创建用户
            User user = new User();
            string userID = user.GetUserID();

            // 密钥生成和导出
            KeyManage keyManage = new KeyManage();

            // 密码唯一，且由用户的用户名和安全序列号唯一生成
            string passwd = (user.get_username() + user.get_sid()).GetHashCode().ToString();
            keyManage.GenerateKeyPairRSA(userID, passwd);
            keyManage.ExportPublicKey(userID, passwd);
            // keyManage.ExportPrivateKey(userID, passwd);//私钥敏感信息不能导出
            keyManage.KeyStoreListKeys(passwd);

            // 模式选择：原理展示/存储模式/调阅模式
            // 用户界面
            while (true)
            {
                ModeManage modeManage = new ModeManage();
                int Mode = modeManage.mode_input(user);
                modeManage.mode_control(Mode, user, passwd);
                Console.WriteLine("程序已结束，按q退出，按其他任意键返回用户界面...");
                if (Console.ReadLine() == "q")
                    break;
            }
        }
    }
}

// 密钥管理类，用于生成密钥对、导出公钥、导出私钥和列出密钥信息
public class KeyManage
{
    // 析构函数，保证释放敏感信息
    ~KeyManage()
    {

    }

    // RSA密钥生成
    public void GenerateKeyPairRSA(string userID, string passwd)
    {
        Console.WriteLine("生成用户密钥");
        Console.WriteLine("-----------------------------------------------------------------------------------------------------------");
        // 初始化密钥库，如果文件不存在则创建
        string file = Path.Combine(Global.pathStringKey, "key.store");
        if (!File.Exists(file))
        {
            KeyStore ks = new KeyStore(@file, passwd);

            // 设置偏好的对称密钥算法
            CypherAlgorithm[] cypher = { CypherAlgorithm.CAST5, CypherAlgorithm.AES_128 };

            // 设置偏好的数字签名（哈希）算法
            HashAlgorithm[] hashing = { HashAlgorithm.SHA1, HashAlgorithm.MD5, HashAlgorithm.SHA256 };

            // 设置偏好的压缩算法
            CompressionAlgorithm[] compression = { CompressionAlgorithm.ZIP, CompressionAlgorithm.UNCOMPRESSED };

            int keySizeInBits = 2048;
            ks.GenerateKeyPair(keySizeInBits, userID, KeyAlgorithm.RSA, passwd, compression, hashing, cypher);

            // 现在可以使用密钥库中的密钥，或者导出它
            Console.WriteLine("用户{0}的密钥（公私钥）已生成，在\"{1}\"中\n", Environment.UserName, file);
        }
        else
        {
            Console.WriteLine("用户{0}的密钥已存在，在\"{1}\"中\n", Environment.UserName, file);
            return;
        }
    }

    // 导出公钥
    public void ExportPublicKey(string userID, string passwd)
    {
        // 初始化密钥库
        string fileStore = Path.Combine(Global.pathStringKey, "key.store");
        string filePublicKey = Path.Combine(Global.pathStringKey, "public_key_exported.asc");
        KeyStore ks = KeyStore.OpenFile(@fileStore, passwd);

        // 导出为ASCII格式
        bool asciiArmored = true;

        // 导出公钥
        if (!File.Exists(filePublicKey))
            ks.ExportPublicKey(@filePublicKey, userID, asciiArmored);
        Console.WriteLine("用户{0}的公钥已导出，在\"{1}\"中\n", Environment.UserName, filePublicKey);
    }

    // 导出私钥
    public void ExportPrivateKey(string userID, string passwd)
    {
        string fileStore = Path.Combine(Global.pathStringKey, "key.store");
        string filePrivateKey = Path.Combine(Global.pathStringKey, "private_key_exported.asc");
        // 初始化密钥库
        KeyStore ks = KeyStore.OpenFile(@fileStore, passwd);

        // 导出为ASCII格式
        bool asciiArmored = true;

        // 导出私钥
        ks.ExportPrivateKey(@filePrivateKey, userID, asciiArmored);
    }

    // 列出密钥信息
    public void KeyStoreListKeys(string passwd)
    {
        Console.WriteLine("当前密钥信息为：");
        string file = Path.Combine(Global.pathStringKey, "key.store");
        // 初始化密钥库
        KeyStore ks = KeyStore.OpenFile(file, passwd);

        KeyPairInformation[] keys = ks.GetKeys();

        StringBuilder sb = new StringBuilder();
        sb.Append("Username".PadRight(15));
        sb.Append("Type".PadRight(10));
        sb.Append("Key Id".PadRight(30));
        sb.Append("Created".PadRight(20));
        sb.Append("User Id");
        Console.WriteLine(sb.ToString());

        foreach (KeyPairInformation key in keys)
        {
            sb.Remove(0, sb.Length);
            sb.Append(Environment.UserName.PadRight(15));
            string keyType = key.HasPrivateKey ? "pub/sec" : "pub";
            sb.Append(keyType.PadRight(10));

            sb.Append(Convert.ToString(key.KeyId).PadRight(30));
            sb.Append(key.CreationTime.ToShortDateString().PadRight(20));

            foreach (string id in key.UserIds)
            {
                sb.Append(id);
            }

            Console.WriteLine(sb.ToString());
            Console.WriteLine("-----------------------------------------------------------------------------------------------------------\n");
        }
    }
}

// 文件管理类，负责文件的签名和加密、解密和签名验证
public class FileManage
{
    // 析构函数，保证释放敏感信息
    ~FileManage()
    {

    }

    // 签名和加密（多人）
    public string SignAndEncryptMultiple(string passwd, string File, string[] all_Authorized_Uers_PublicKey, string userID)
    {
        // 获取文件名（不含拓展名）
        string extension = Path.GetExtension(File);
        string fileNameWithoutExtension = Path.GetFileNameWithoutExtension(File);
        string fileNameRandom = Path.GetRandomFileName();
        string fileNameRandomWithoutExtension = Path.GetFileNameWithoutExtension(fileNameRandom);
        string newFile = fileNameWithoutExtension + fileNameRandomWithoutExtension + extension + ".gpg";

        // 创建PGP实例
        PGPLib pgp = new PGPLib();
        // 是否使用ASCII格式
        bool asciiArmor = true;
        // 是否添加完整性检查
        bool withIntegrityCheck = false;

        // 文件目录
        string[] input_file = { File };
        string file_public_key = Path.Combine(Global.pathStringKey, "public_key_exported.asc");
        string file_private_key = Path.Combine(Global.pathStringKey, "private_key_exported.asc");
        string output_file = Path.Combine(Global.pathStringFile, newFile);
        string[] recipientsPublicKeys = all_Authorized_Uers_PublicKey;

        KeyManage keyManage = new KeyManage();
        keyManage.ExportPrivateKey(userID, passwd); // 导出私钥
        ClearTool clearTool = new ClearTool();

        // 签名和加密文件
        pgp.SignAndEncryptFiles(input_file, file_private_key, passwd, recipientsPublicKeys, output_file, asciiArmor, withIntegrityCheck);

        // 删除私钥
        clearTool.ClearDeletFile(file_private_key);

        return output_file;
    }

    // 签名和加密（单人）
    public string SignAndEncryptSinge(string passwd, string File, string userID)
    {
        // 获取文件名（不含拓展名）
        string extension = Path.GetExtension(File);
        string fileNameWithoutExtension = Path.GetFileNameWithoutExtension(File);
        string fileNameRandom = Path.GetRandomFileName();
        string fileNameRandomWithoutExtension = Path.GetFileNameWithoutExtension(fileNameRandom);
        string newFile = fileNameWithoutExtension + fileNameRandomWithoutExtension + extension + ".gpg";

        // 创建PGP实例
        PGPLib pgp = new PGPLib();
        // 是否使用ASCII格式
        bool asciiArmor = true;
        // 是否添加完整性检查
        bool withIntegrityCheck = false;

        // 文件目录
        string input_file = File;
        string file_public_key = Path.Combine(Global.pathStringKey, "public_key_exported.asc");
        string file_private_key = Path.Combine(Global.pathStringKey, "private_key_exported.asc");
        string output_file = Path.Combine(Global.pathStringFile, newFile);

        KeyManage keyManage = new KeyManage();
        keyManage.ExportPrivateKey(userID, passwd); // 导出私钥
        ClearTool clearTool = new ClearTool();

        // 签名和加密文件
        pgp.SignAndEncryptFile(input_file, file_private_key, passwd, file_public_key, output_file, asciiArmor, withIntegrityCheck);

        // 删除私钥
        clearTool.ClearDeletFile(file_private_key);

        return output_file;
    }

    // 签名和加密字符串
    public string SignAndEncryptString(string plainText, string passwd, string userID)
    {
        // 创建PGP实例
        PGPLib pgp = new PGPLib();
        string file_public_key = Path.Combine(Global.pathStringKey, "public_key_exported.asc");
        string file_private_key = Path.Combine(Global.pathStringKey, "private_key_exported.asc");

        KeyManage keyManage = new KeyManage();
        keyManage.ExportPrivateKey(userID, passwd); // 导出私钥
        ClearTool clearTool = new ClearTool();

        // 签名和加密字符串
        string encryptedAndSignedString = pgp.SignAndEncryptString(plainText, new FileInfo(file_private_key), passwd, new FileInfo(file_public_key));

        // 删除私钥
        clearTool.ClearDeletFile(file_private_key);

        return encryptedAndSignedString;
    }

    // 验证签名
    public bool Verify(string passwd, string File, string[] All_User_Public_key, string[] All_Users, string userID)
    {
        string originalFile = Path.GetFileNameWithoutExtension(File);
        string extension = Path.GetExtension(File);
        string filetmp = originalFile + "Tmp" + extension;

        // 创建PGP实例
        PGPLib pgp = new PGPLib();

        // 文件目录
        string input_file = File;
        string file_private_key = Path.Combine(Global.pathStringKey, "private_key_exported.asc");
        string output_file = Path.Combine(Global.pathStringFile, filetmp);

        KeyManage keyManage = new KeyManage();
        keyManage.ExportPrivateKey(userID, passwd); // 导出私钥
        ClearTool clearTool = new ClearTool();

        string user_tmp = "错误";
        for (int i = 0; i < All_Users.Length; i++)
        {
            // 先解密再验证签名
            SignatureCheckResult signatureCheck = pgp.DecryptAndVerifyFile(input_file, file_private_key, passwd, All_User_Public_key[i], output_file);

            if (signatureCheck == SignatureCheckResult.SignatureVerified && All_Users[i] == Environment.UserName)
            {
                // 删除私钥和临时文件
                clearTool.ClearDeletFile(file_private_key);
                clearTool.ClearDeletFile(output_file);
                Console.WriteLine($"身份认证成功，您的身份为{All_Users[i]},创建文件成功");
                return true;
            }
            user_tmp = All_Users[i];
        }

        // 删除私钥和临时文件
        clearTool.ClearDeletFile(file_private_key);
        clearTool.ClearDeletFile(output_file);
        Console.WriteLine($"身份认证失败，您的身份为{user_tmp},创建文件失败");
        return false;
    }

    // 解密和验证签名
    public void DecryptAndVerify(string passwd, string File, string[] All_User_Public_key, string[] All_Users, string userID)
    {
        string originalFile = Path.GetFileNameWithoutExtension(File);
        PGPLib pgp = new PGPLib();

        // 文件目录
        string input_file = File;
        string file_private_key = Path.Combine(Global.pathStringKey, "private_key_exported.asc");
        string output_file = Path.Combine(Global.pathStringFile, originalFile);

        KeyManage keyManage = new KeyManage();
        keyManage.ExportPrivateKey(userID, passwd); // 导出私钥
        ClearTool clearTool = new ClearTool();

        // 解密并获取原始文件名
        string originalFileName = pgp.DecryptFile(input_file, file_private_key, passwd, output_file);

        Console.WriteLine($"您的身份为用户\"{Environment.UserName}\"");
        Console.WriteLine($"文件调阅成功，原文件名为{originalFileName},解密后的文件在{output_file}中");

        for (int i = 0; i < All_Users.Length; i++)
        {
            // 先解密再验证签名
            SignatureCheckResult signatureCheck = pgp.DecryptAndVerifyFile(input_file, file_private_key, passwd, All_User_Public_key[i], output_file);

            if (signatureCheck == SignatureCheckResult.SignatureVerified)
            {
                Console.WriteLine($"签名验证成功，该文件是由用户{All_Users[i]}创建的");
                // 删除私钥
                clearTool.ClearDeletFile(file_private_key);
                break;
            }
            else if (signatureCheck == SignatureCheckResult.NoSignatureFound)
            {
                Console.WriteLine("此文件未数字签名");
                // 删除私钥
                clearTool.ClearDeletFile(file_private_key);
                break;
            }
            else if (signatureCheck == SignatureCheckResult.SignatureBroken)
            {
                Console.WriteLine("文件的签名已损坏或伪造 ");
                // 删除私钥
                clearTool.ClearDeletFile(file_private_key);
                break;
            }
            else if (i == All_Users.Length - 1 && signatureCheck == SignatureCheckResult.PublicKeyNotMatching)
            {
                Console.WriteLine("提供的公钥与签名不匹配");
                // 删除私钥
                clearTool.ClearDeletFile(file_private_key);
            }
        }
    }

    // 解密和验证签名字符串
    public void DecryptAndVerifyString(string signedAndEncryptedMessage, string passwd, string userID)
    {
        string file_public_key = Path.Combine(Global.pathStringKey, "public_key_exported.asc");
        string file_private_key = Path.Combine(Global.pathStringKey, "private_key_exported.asc");
        string plainTextExtracted;

        // 创建PGP实例
        PGPLib pgp = new PGPLib();

        KeyManage keyManage = new KeyManage();
        keyManage.ExportPrivateKey(userID, passwd); // 导出私钥
        ClearTool clearTool = new ClearTool();

        // 解密并验证
        SignatureCheckResult signatureCheck = pgp.DecryptAndVerifyString(signedAndEncryptedMessage, new FileInfo(file_private_key), passwd, new FileInfo(file_public_key), out plainTextExtracted);

        // 删除私钥
        clearTool.ClearDeletFile(file_private_key);

        // 打印结果
        if (signatureCheck == SignatureCheckResult.SignatureVerified)
        {
            Console.WriteLine("签名验证成功");
        }
        else if (signatureCheck == SignatureCheckResult.SignatureBroken)
        {
            Console.WriteLine("文件的签名已损坏或伪造 ");
        }
        else if (signatureCheck == SignatureCheckResult.PublicKeyNotMatching)
        {
            Console.WriteLine("提供的公钥与签名不匹配");
        }
        else if (signatureCheck == SignatureCheckResult.NoSignatureFound)
        {
            Console.WriteLine("此文件未数字签名");
        }

        Console.WriteLine($"用您的私钥先解密，再用您的公钥验证签名，得到的字符串为\n{plainTextExtracted}");
    }
}

public class ClearTool
{
    ~ClearTool()
    {

    }
    /// <summary>
    /// 清空目录或文件
    /// </summary>
    public void ClearDelet(string path)
    {
        if (File.Exists(path)) ClearDeletFile(path);
        if (Directory.Exists(path)) ClearDeletDirectory(path);
    }

    /// <summary>
    /// 先清空目录中的所有文件和子目录内容，再删除当前目录
    /// </summary>
    public void ClearDeletDirectory(string dir)
    {
        if (Directory.Exists(dir))
        {
            // 清除目录下的所有文件
            foreach (String iteam in Directory.GetFiles(dir))
            {
                ClearDeletFile(iteam);
            }

            // 清除目录下的所有子目录
            foreach (String iteam in Directory.GetDirectories(dir))
            {
                ClearDeletDirectory(iteam);
            }

            String newName = System.IO.Directory.GetParent(dir).FullName + "\\$";
            while (File.Exists(newName)) newName += "$";

            // 清除当前目录
            Directory.Move(dir, newName);   // 重命名当前目录，清除目录名信息
            Directory.Delete(newName);      // 清除当前目录
        }
    }

    /// <summary>
    /// 先清空文件内容，再删除
    /// </summary>
    public void ClearDeletFile(string file)
    {
        ClearFile(file);                // 清空文件内容
        if (File.Exists(file))
        {
            String newName = System.IO.Directory.GetParent(file).FullName + "\\$";
            while (File.Exists(newName)) newName += "$";

            File.Move(file, newName);   // 重命名文件，清除文件名称信息
            File.Delete(newName);       // 删除文件
        }
    }

    /// <summary>
    /// 清空文件内容
    /// </summary>
    public static void ClearFile(string file)
    {
        if (File.Exists(file))
        {
            int SIZE = 1024 * 10240;
            byte[] array = new byte[SIZE];
            array.Initialize();

            FileStream s = new FileStream(file, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite, SIZE, FileOptions.RandomAccess);

            // 清空原有文件内容
            while (s.Position + SIZE <= s.Length - 1)
            {
                s.Write(array, 0, SIZE);
            }
            int reminds = (int)(s.Length - s.Position);
            if (reminds > 0) s.Write(array, 0, reminds);

            // 清除文件长度信息
            s.SetLength(0);
            s.Close();
        }
    }

}
