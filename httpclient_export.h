#ifndef HTTPCLIENT_EXPORT_H
#define HTTPCLIENT_EXPORT_H

#if defined(WIN32)
#if defined(HTTPCLIENT_DLL_BUILD)
#define HTTPCLIENT_API __declspec(dllexport)
#elif defined(USE_HTTPCLIENT_DLL)
#define HTTPCLIENT_API __declspec(dllimport)
#else
#define HTTPCLIENT_API
#endif  // defined(HTTPCLIENT_DLL_BUILD)
#else  // defined(WIN32)
#if defined(HTTPCLIENT_DLL_BUILD)
#define HTTPCLIENT_API __attribute__((visibility("default")))
#else
#define HTTPCLIENT_API
#endif  // defined(HTTPCLIENT_DLL_BUILD)
#endif

#endif // HTTPCLIENT_EXPORT_H
