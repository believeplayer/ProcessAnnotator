#pragma once

#include <string>
#include <cstddef>

// SHA-256 hex (lowercase), empty on failure.
// Cached by path+size+mtime in %LOCALAPPDATA%\ProcessAnnotator.
std::wstring FileSha256(const std::wstring& path);
void LoadHashCache();
void SaveHashCache();
size_t HashCacheSize();
