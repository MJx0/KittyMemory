#pragma once

#include "KittyUtils.hpp"

#define KT_IO_CHUNK_SIZE ((size_t)(1024 * 1024))

/**
 * @brief This class provides an interface for file operations.
 */
class KittyIOFile
{
private:
    int _fd;
    std::string _filePath;
    int _flags;
    mode_t _mode;
    int _error;

public:
    /**
     * @brief Default constructor creating an uninitialized file object.
     */
    KittyIOFile() : _fd(-1), _flags(0), _mode(0), _error(0)
    {
    }

    /**
     * @brief Constructs a new KittyIOFile object with file path, flags, and optional mode.
     *
     * @param filePath The path to the file.
     * @param flags The flags for opening the file.
     * @param mode The mode/permissions for opening the file (default: 0).
     */
    KittyIOFile(const std::string &filePath, int flags, mode_t mode = 0)
        : _fd(-1), _filePath(filePath), _flags(flags), _mode(mode), _error(0)
    {
    }

    ~KittyIOFile()
    {
        if (_fd >= 0)
        {
            close();
        }
    }

    KittyIOFile(const KittyIOFile &) = delete;
    KittyIOFile &operator=(const KittyIOFile &) = delete;

    /**
     * @brief Move constructor. Transfers ownership of the file descriptor.
     */
    KittyIOFile(KittyIOFile &&other) noexcept
        : _fd(other._fd), _filePath(std::move(other._filePath)), _flags(other._flags), _mode(other._mode),
          _error(other._error)
    {
        other._fd = -1;
        other._error = 0;
    }

    /**
     * @brief Move assignment operator. Closes current file descriptor and transfers ownership.
     */
    KittyIOFile &operator=(KittyIOFile &&other) noexcept
    {
        if (this != &other)
        {
            close();

            _fd = other._fd;
            _filePath = std::move(other._filePath);
            _flags = other._flags;
            _mode = other._mode;
            _error = other._error;

            other._fd = -1;
            other._error = 0;
        }
        return *this;
    }

    /**
     * @brief Opens the file.
     *
     * @return true if the file was opened successfully, false otherwise.
     */
    bool open();

    /**
     * @brief Closes the file.
     *
     * @return true if the file was closed successfully, false otherwise.
     */
    bool close();

    /**
     * @brief Returns the last error.
     *
     * @return The last error code.
     */
    inline int lastError() const
    {
        return _error;
    }

    /**
     * @brief Returns the last error message.
     *
     * @return The last error message.
     */
    inline std::string lastStrError() const
    {
        return _error ? strerror(_error) : "";
    }

    /**
     * @brief Returns the file descriptor.
     *
     * @return The file descriptor.
     */
    inline int fd() const
    {
        return _fd;
    }

    /**
     * @brief Returns the file path.
     *
     * @return The file path.
     */
    inline std::string path() const
    {
        return _filePath;
    }

    /**
     * @brief Returns the file flags.
     *
     * @return The file flags.
     */
    inline int flags() const
    {
        return _flags;
    }

    /**
     * @brief Returns the file mode.
     *
     * @return The file mode.
     */
    inline mode_t mode() const
    {
        return _mode;
    }

    /**
     * @brief Reads data from the file and advances file pointer.
     *
     * @param buffer The buffer to read into.
     * @param len The number of bytes to read.
     * @return The number of bytes read, or -1 on error.
     */
    ssize_t read(void *buffer, size_t len);

    /**
     * @brief Writes data to the file and advances file pointer.
     *
     * @param buffer The buffer to write from.
     * @param len The number of bytes to write.
     * @return The number of bytes written, or -1 on error.
     */
    ssize_t write(const void *buffer, size_t len);

    /**
     * @brief Reads data from the file at a given offset without changing file pointer.
     *
     * @param offset The offset to read from.
     * @param buffer The buffer to read into.
     * @param len The number of bytes to read.
     * @return The number of bytes read, or -1 on error.
     */
    ssize_t pread(kt_off64_t offset, void *buffer, size_t len);

    /**
     * @brief Writes data to the file at a given offset without changing file pointer.
     *
     * @param offset The offset to write to.
     * @param buffer The buffer to write from.
     * @param len The number of bytes to write.
     * @return The number of bytes written, or -1 on error.
     */
    ssize_t pwrite(kt_off64_t offset, const void *buffer, size_t len);

    /**
     * @brief Checks if the file exists.
     *
     * @return true if the file exists, false otherwise.
     */
    inline bool exists() const
    {
        return access(_filePath.c_str(), F_OK) != -1;
    }

    /**
     * @brief Checks if the file can be read.
     *
     * @return true if the file can be read, false otherwise.
     */
    inline bool canRead() const
    {
        return access(_filePath.c_str(), R_OK) != -1;
    }

    /**
     * @brief Checks if the file can be written.
     *
     * @return true if the file can be written, false otherwise.
     */
    inline bool canWrite() const
    {
        return access(_filePath.c_str(), W_OK) != -1;
    }

    /**
     * @brief Checks if the file can be executed.
     *
     * @return true if the file can be executed, false otherwise.
     */
    inline bool canExecute() const
    {
        return access(_filePath.c_str(), X_OK) != -1;
    }

    /**
     * @brief Removes the file.
     *
     * @return true if the file was removed successfully, false otherwise.
     */
    inline bool remove()
    {
        _error = (unlink(_filePath.c_str()) == -1) ? errno : 0;
        return _error == 0;
    }

    /**
     * @brief Retrieves information about the file.
     *
     * @return The file information.
     */
    inline kt_stat64_t info()
    {
        kt_stat64_t s = {};
        _error = (kt_stat64(_filePath.c_str(), &s) == -1) ? errno : 0;
        return s;
    }

    /**
     * @brief Checks if the file is a regular file.
     *
     * @return true if the file is a regular file, false otherwise.
     */
    inline bool isFile()
    {
        auto s = info();
        return _error == 0 && S_ISREG(s.st_mode);
    }

    /**
     * @brief Reads the contents of the file into a string.
     *
     * @param str The string to read into.
     * @return true if the file was read successfully, false otherwise.
     */
    bool readToString(std::string *str);

    /**
     * @brief Reads the contents of the file into a buffer.
     *
     * @param buf The buffer to read into.
     * @return true if the file was read successfully, false otherwise.
     */
    bool readToBuffer(std::vector<char> *buf);

    /**
     * @brief Copies the contents of the file to another file.
     *
     * @param filePath The file path to write to.
     * @return true if the file was written successfully, false otherwise.
     */
    bool copyToFile(const std::string &filePath)
    {
        KittyIOFile f(filePath, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
        return f.open() && copyToFd(f.fd());
    }

    /**
     * @brief Writes the contents of the file to a file descriptor.
     *
     * @param fd The file descriptor.
     * @return true if the file was written successfully, false otherwise.
     */
    bool copyToFd(int fd);

    /**
     * @brief Reads the contents of a file into a string.
     *
     * @param filePath The file path to read from.
     * @param str The string to read into.
     * @return true if the file was read successfully, false otherwise.
     */
    inline static bool readFileToString(const std::string &filePath, std::string *str)
    {
        KittyIOFile f(filePath, O_RDONLY | O_CLOEXEC);
        return f.open() && f.readToString(str);
    }

    /**
     * @brief Reads the contents of a file into a buffer.
     *
     * @param filePath The file path to read from.
     * @param buf The buffer to read into.
     * @return true if the file was read successfully, false otherwise.
     */
    inline static bool readFileToBuffer(const std::string &filePath, std::vector<char> *buf)
    {
        KittyIOFile f(filePath, O_RDONLY | O_CLOEXEC);
        return f.open() && f.readToBuffer(buf);
    }

    /**
     * @brief Copies the contents of a file to another file.
     *
     * @param srcFilePath The source file path.
     * @param dstFilePath The destination file path.
     * @return true if the file was copied successfully, false otherwise.
     */
    inline static bool copy(const std::string &srcFilePath, const std::string &dstFilePath)
    {
        KittyIOFile f(srcFilePath, O_RDONLY | O_CLOEXEC);
        return f.open() && f.copyToFile(dstFilePath);
    }

    /**
     * @brief Lists files in a directory.
     *
     * @param dir The directory path.
     * @param cb The callback function to be called for each file.
     */
    static bool listFilesCallback(const std::string &dir, std::function<bool(const std::string &)> cb);

    /**
     * @brief Recursively creates a directory path.
     *
     * This function creates all intermediate directories in the given path,
     * similar to the behavior of `mkdir -p` on POSIX systems.
     *
     * @param path The full directory path to create (absolute or relative).
     * @param mode The permissions to use when creating directories (default: 0755).
     *
     * @return true if the directory exists or was successfully created,
     *         false if an error occurred.
     *
     * @note If a directory already exists, it is not treated as an error.
     *
     * @warning This function does not verify whether an existing path component
     *          is a directory or a file. If a file exists in the path, creation
     *          will fail.
     *
     *
     * @see mkdir(2)
     */
    static bool createDirectoryRecursive(const std::string &path, mode_t mode = 0755);
};