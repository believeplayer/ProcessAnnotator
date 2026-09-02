#pragma once

// Включает SeDebugPrivilege для текущего процесса.
// Нужно для доступа к большинству процессов.
bool EnableDebugPrivilege();
