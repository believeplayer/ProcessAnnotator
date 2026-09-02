#pragma once

#include <string>
#include <optional>

struct SignatureInfo {
    bool isSigned = false;
    bool isValid = false;
    std::wstring publisher;
    std::wstring status;   // "Microsoft", "AMD", "Valid", "Invalid", "Unsigned"
};

// Проверка подписи с кэшем (память + %LOCALAPPDATA%\ProcessAnnotator)
SignatureInfo VerifySignature(const std::wstring& filePath);

// Загрузить/сохранить кэш
void LoadSignatureCache();
void SaveSignatureCache();
size_t SignatureCacheSize();
size_t SignatureCacheHits();
