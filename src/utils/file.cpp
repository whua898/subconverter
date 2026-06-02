#include <string>
#include <fstream>
#include <sys/stat.h>

#include "utils/string.h"

bool isInScope(const std::string &path)
{
#ifdef _WIN32
    if(path.find(":\\") != path.npos || path.find("..") != path.npos)
        return false;
#else
    // V5.0 SOP: 放宽路径检查。拒绝绝对路径 / 开头 和 .. 目录穿越
    // 但允许 ./base/mellow.conf、base/mellow.conf、mellow.conf 等相对路径
    if(path.find("..") != path.npos)
        return false;
    // 绝对路径 /... 拒绝
    if(startsWith(path, "/"))
        return false;
#endif // _WIN32
    return true;
}

std::string fileGet(const std::string &path, bool scope_limit)
{
    std::string content;
    if(scope_limit && !isInScope(path))
        return "";
    std::FILE *fp = std::fopen(path.c_str(), "rb");
    if(fp)
    {
        std::fseek(fp, 0, SEEK_END);
        long tot = std::ftell(fp);
        content.resize(tot);
        std::rewind(fp);
        std::fread(&content[0], 1, tot, fp);
        std::fclose(fp);
    }
    return content;
}

bool fileExist(const std::string &path, bool scope_limit)
{
    if(scope_limit && !isInScope(path))
        return false;
    struct stat st;
    return stat(path.data(), &st) == 0 && S_ISREG(st.st_mode);
}

bool fileCopy(const std::string &source, const std::string &dest)
{
    std::ifstream infile;
    std::ofstream outfile;
    infile.open(source, std::ios::binary);
    if(!infile) return false;
    outfile.open(dest, std::ios::binary);
    if(!outfile) return false;
    try { outfile << infile.rdbuf(); }
    catch (std::exception &e) { return false; }
    infile.close(); outfile.close();
    return true;
}

int fileWrite(const std::string &path, const std::string &content, bool overwrite)
{
    const char *mode = overwrite ? "wb" : "ab";
    std::FILE *fp = std::fopen(path.c_str(), mode);
    std::fwrite(content.c_str(), 1, content.size(), fp);
    std::fclose(fp);
    return 0;
}