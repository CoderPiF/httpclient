//
//  Created by Pi on 2019/10/3.
//

#ifndef REQUESTS_HPP
#define REQUESTS_HPP

#include <memory>
#include <string>
#include <map>
#include <curl/curl.h>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <vector>
#include <list>
#include <thread>
#include <queue>
#include <atomic>
#include "httpclient_export.h"

namespace http_client
{
    enum class HTTPCLIENT_API Method
    {
        GET, POST
    };

    using HeaderFields = std::map<std::string, std::string>;

    struct HTTPCLIENT_API ResponseInfo final
    {
        using Ptr = std::shared_ptr<ResponseInfo>;

        int64_t httpVersion = 0;

        CURLcode resCode = CURLE_OK;
        int64_t statusCode = 0;

        HeaderFields headers;

        std::string body;

        struct {
            double totalTime = 0;
            double nameLookupTime = 0;
            double connectTime = 0;
            double appConnectTime = 0;
            double preTransferTime = 0;
            double startTransferTime = 0;
            double redirectTime = 0;
            int64_t redirectCount = 0;
        } statistics;

        bool isSuccess() const { return resCode == CURLE_OK && 200 <= statusCode && statusCode < 300; }
    };

    struct HTTPCLIENT_API Progress final
    {
        enum Operation
        {
            Continue = 0,
            Stop = 1
        };

        using Handler = std::function<Operation (const Progress &)>;

        struct
        {
            curl_off_t total;
            curl_off_t current;
        } download, upload;
    };

    class RequestInfo;
    class HTTPCLIENT_API Task final
    {
    public:
        using Ptr = std::shared_ptr<Task>;
        using FailHandler = std::function<void (const Task *, int32_t resCode, int64_t statusCode, const ResponseInfo::Ptr &respInfo)>;
        using SuccessHandler = std::function<void (const Task *, const ResponseInfo::Ptr &respInfo)>;
        using FinishHandler = std::function<void (const Task *, const ResponseInfo::Ptr &respInfo)>;
        using ProgressHandler = std::function<void (const Task *, const Progress &progress)>;

        enum State
        {
            Init = 0, Pending, Success, Fail, Canceled, Last
        };

        size_t taskId() const;
        State state() const;

        const RequestInfo & info() const;

        void wait() const;
        bool cancel();

        Task * onProgress(const ProgressHandler &handler);
        Task * onFail(const FailHandler &handler);
        Task * onSuccess(const SuccessHandler &handler);
        Task * onFinish(const FinishHandler &handler);

        const ProgressHandler & progress() const;
        const FailHandler & fail() const;
        const SuccessHandler & success() const;
        const FinishHandler & finish() const;

        ~Task();
    private:
        friend class Session;
        Task(size_t taskId, const RequestInfo &info, const std::string &toFile);

        bool changeState(State state);
        void notifyFail(int32_t resCode, int64_t statusCode, const ResponseInfo::Ptr &respInfo);
        void notifySuccess(const ResponseInfo::Ptr &respInfo);
        void notifyProgress(const Progress &progress);

        const std::string & saveFilePath() const;

        mutable std::recursive_mutex _mutex;
        mutable std::condition_variable_any _cv;

        std::atomic<size_t> _taskId;
        State _state = State::Init;
        ProgressHandler _progress;
        FailHandler _fail;
        SuccessHandler _success;
        FinishHandler _finish;

        int32_t _resCode = -1;
        int64_t _statusCode = -1;
        ResponseInfo::Ptr _response;
        std::shared_ptr<RequestInfo> _info;
        std::string _saveToFilePath;
    };

    struct HTTPCLIENT_API ParamBody
    {
        using Data = std::map<std::string, std::string>;
        ParamBody & param(const std::string &key, const std::string &value);

        Data data;
    };

    struct HTTPCLIENT_API XWwwFormUrlencodedBody : public ParamBody {};
    struct HTTPCLIENT_API FormDataBody
    {
        struct DataValue
        {
            enum Type { Text, File };
            Type type = Text;
            std::string mimeType;
            std::string fileName;
            std::string value;
        };
        using Data = std::map<std::string, DataValue>;

        FormDataBody & param(const std::string &key, const std::string &value);
        FormDataBody & file(const std::string &key, const std::string &fileName, const std::string &filePath, const std::string &mimeType = "");

        Data data;
    };

    class Session;
    class HTTPCLIENT_API Request final
    {
    public:
        using Ptr = std::shared_ptr<Request>;

        // header
        Request * header(const std::string &key, const std::string &value);
        Request * userAgent(const std::string &userAgent);

        // body
        Request * paramBody(std::function<void(ParamBody &body)> maker);
        Request * rawBody(const std::string &raw, const std::string &contentType);
        Request * xWwwFormUrlencodedBody(std::function<void(XWwwFormUrlencodedBody &body)> maker);
        Request * formDataBody(std::function<void(FormDataBody &body)> maker);

        // auth
        Request * auth(const std::string &username, const std::string &password);

        // config
        Request * timeout(int32_t seconds);
        Request * redirects(bool isFollowRedirects, int64_t maxRedirects = -1);
        Request * noSignal(bool isNoSignal = true);

        Request * sslVerifyHost(bool verify);
        Request * sslVerifyPeer(bool verify);
        Request * caInfoFilePath(const std::string &caInfoFilePath);
        Request * certPath(const std::string &certPath);
        Request * certType(const std::string &certType);
        Request * keyPath(const std::string &keyPath);
        Request * keyPassword(const std::string &keyPassword);

        Request * proxy(const std::string &uriProxy);
        Request * unixSocketPath(const std::string &unixSocketPath);
        Request * host(const std::string &hostName, uint16_t port,
                       const std::string &ip);
        Request * host(const std::string &hostName, uint16_t port,
                       const std::vector<std::string> &ips);

        // session
        Request * session(const std::shared_ptr<Session> &session);

        // send
        Task::Ptr send();
        Task::Ptr sendAndDownload(const std::string &toFile);

    private:
        friend class Requests;
        friend class Session;
        Request(Method method, const std::string &url);

        std::shared_ptr<RequestInfo> _info;
        std::weak_ptr<Session> _session;
    };

    class HTTPCLIENT_API Session final : public std::enable_shared_from_this<Session>
    {
    public:
        enum { DefaultThreadNum = 3 };

        using Ptr = std::shared_ptr<Session>;
        const std::string & baseUrl() const;
        Request::Ptr request(Method method, const std::string &path);

        void maxThreadNum(size_t num);
        size_t maxThreadNum() const;

        // disable copy
        Session(const Session &) = delete;
        const Session & operator = (const Session &) = delete;

        ~Session();

    private:
        friend class Requests;
        Session(const std::string &baseUrl);

        friend class Request;
        Task::Ptr send(const Request &request);
        Task::Ptr sendAndDownload(const Request &request, const std::string &toFile);

        void createWorkerIfNeed();

        bool isRunning(uint64_t id);
        Task::Ptr popTask();
        Task::Ptr addTask(const Request &request, const std::string &toFile);

        void recordRunningTask(const Task::Ptr &task);
        void removeRunningTask(const Task::Ptr &task);
        void cancelAllRunningTasks();

        static void Run(Session *session, uint64_t id);

        std::string _baseUrl;

        std::atomic<bool> _isInDestory;
        CURLSH *_curlShared = nullptr;
        std::mutex _curlSharedMutex[CURL_LOCK_DATA_LAST];

        mutable std::recursive_mutex _taskMutex;
        std::condition_variable_any _taskCV;
        std::queue<Task::Ptr> _taskQueue;
        uint64_t _nextWorkerId = 0;
        std::vector<uint64_t> _workerIds;
        std::list<std::thread> _threadList;

        std::atomic<size_t> _nextTaskId;
        std::atomic<size_t> _maxThreadNum;

        std::mutex _runningTaskMutex;
        std::map<const Task *, Task::Ptr> _runningTask;
    };

    class HTTPCLIENT_API Requests final
    {
    public:
        static void init(); // call in main thread, cause curl global init not thread safe
        static void destory(); // call in main thread

        static Session * sharedSession();

        static Session::Ptr session(const std::string &baseUrl = "");
        static Request::Ptr request(Method method, const std::string &url);
    };
}

#endif /* REQUESTS_HPP */
