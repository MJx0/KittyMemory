#pragma once

#include <string>
#include <cstdint>
#include <vector>
#include <utility>

#include "KittyMemory.hpp"

namespace KittyScanner
{
    /**
     * Search for bytes within a memory range and return all results
     * 
     * @start: search start address
     * @end: search end address
     * @bytes: bytes to search
     * @mask: bytes mask x/?
     *
     * @return vector list of all found bytes addresses
     */
    std::vector<uintptr_t> findBytesAll(const uintptr_t start, const uintptr_t end, const char *bytes, const std::string& mask);
    
    /**
     * Search for bytes within a memory range and return first result
     * 
     * @start: search start address
     * @end: search end address
     * @bytes: bytes to search
     * @mask: bytes mask x/?
     *
     * @return first found bytes address
     */
     uintptr_t findBytesFirst(const uintptr_t start, const uintptr_t end, const char *bytes, const std::string& mask);

    /**
     * Search for hex within a memory range and return all results
     * 
     * @start: search start address
     * @end: search end address
     * @hex: hex to search
     * @mask: hex mask x/?
     *
     * @return vector list of all found hex addresses
     */
    std::vector<uintptr_t> findHexAll(const uintptr_t start, const uintptr_t end, std::string hex, const std::string& mask);
    
    /**
     * Search for hex within a memory range and return first result
     * 
     * @start: search start address
     * @end: search end address
     * @hex: hex to search
     * @mask: hex mask x/?
     *
     * @return first found hex address
     */
    uintptr_t findHexFirst(const uintptr_t start, const uintptr_t end, std::string hex, const std::string& mask);

    /**
     * Search for ida pattern within a memory range and return all results
     *
     * @param start: search start address
     * @param end: search end address
     * @param pattern: hex bytes and wildcard "?" ( FF DD ? 99 CC ? 00 )
     *
     * @return vector list of all found pattern addresses
     */
    std::vector<uintptr_t> findIdaPatternAll(const uintptr_t start, const uintptr_t end, const std::string& pattern);

    /**
     * Search for ida pattern within a memory range and return first result
     *
     * @param start: search start address
     * @param end: search end address
     * @param pattern: hex bytes and wildcard "?" ( FF DD ? 99 CC ? 00 )
     *
     * @return first found pattern address
     */
    uintptr_t findIdaPatternFirst(const uintptr_t start, const uintptr_t end, const std::string& pattern);

    /**
     * Search for data within a memory range and return all results
     * 
     * @start: search start address
     * @end: search end address
     * @data: data to search
     * @size: data size
     *
     * @return vector list of all found data addresses
     */
    std::vector<uintptr_t> findDataAll(const uintptr_t start, const uintptr_t end, const void *data, size_t size);
    
    
    /**
     * Search for data within a memory range and return first result
     * 
     * @start: search start address
     * @end: search end address
     * @data: data to search
     * @size: data size
     *
     * @return first found data address
     */
    uintptr_t findDataFirst(const uintptr_t start, const uintptr_t end, const void *data, size_t size);

#ifdef __ANDROID__
    
    class RegisterNativeFn
    {
    public:
        char *name;
        char *signature;
        void *fnPtr;

        RegisterNativeFn() : name(nullptr), signature(nullptr), fnPtr(nullptr) {}
        inline bool isValid() const { return (name != nullptr && signature != nullptr && fnPtr != nullptr); }
    };

    /**
     * search for string "name" references to find the JNINativeMethod array
     */
    RegisterNativeFn findRegisterNativeFn(const std::vector<KittyMemory::ProcMap> &maps, const std::string &name);

    /**
     * lookup symbol name in a loaded shared object
     * @return the absolute address of the symbol
     */
    uintptr_t findSymbol(const KittyMemory::ProcMap &baseMap, const std::string &symbol_name);
    /**
     * lookup symbol name in a loaded shared object
     * @return the absolute address of the symbol
     */
    uintptr_t findSymbol(uintptr_t libBase, const std::string &symbol_name);
    /**
     * lookup symbol name in a loaded shared object
     * @return the absolute address of the symbol
     */
    uintptr_t findSymbol(const std::string &lib, const std::string &symbol_name);

    /**
     * lookup symbol name in all loaded shared objects
     * @return a vector of symbol absolute address and the library pathname where the symbol was found in
     */
    std::vector<std::pair<uintptr_t, std::string>> findSymbolAll(const std::string &symbol_name);

#endif // __ANDROID__

}