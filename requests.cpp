//
//  Created by Pi on 2019/10/3.
//

#include "requests.hpp"
#include <set>
#include <ctype.h>

#define __NS_BEGIN namespace http_client {
#define __NS_END }

__NS_BEGIN

// MARK: - impl
namespace
{
    ResponseInfo::Ptr doRequest(const RequestInfo &info, const std::string &toFile,
                                CURL *curlHandler, const Progress::Handler &progressHandler);
}

// MARK: - structure
struct RequestBody final
{
    enum class Type
    {
        x_www_form_urlencoded,
        form_data,
        raw
    };

    Type type = Type::x_www_form_urlencoded;
    // union? no pointer for easy copy
    std::string raw;
    XWwwFormUrlencodedBody params;
    FormDataBody formData;
};

struct HostResolve
{
    std::string host;
    std::vector<std::string> ips;
    uint16_t port = 0;

    bool operator < (const HostResolve &other) const
    {
        return port < other.port || host < other.host;
    }
};

struct RequestInfo final
{
    Method method = Method::GET;
    std::string url;
    HeaderFields headers;
    std::string userAgent;

    ParamBody param;
    RequestBody body;

    struct {
        std::string username;
        std::string password;
    } auth;

    int32_t timeout = 0;
    bool followRedirects = true;
    int64_t maxRedirects = -1;
    bool noSignal = true;

    bool sslVerifyHost = true;
    bool sslVerifyPeer = true;
    std::string caInfoFilePath;
    std::string certPath;
    std::string certType;
    std::string keyPath;
    std::string keyPassword;
    std::string uriProxy;
    std::string unixSocketPath;

    std::set<HostResolve> hosts;
};

// MARK: - body
ParamBody & ParamBody::param(const std::string &key, const std::string &value)
{
    data[key] = value;
    return *this;
}

FormDataBody & FormDataBody::param(const std::string &key, const std::string &value)
{
    DataValue d;
    d.type = DataValue::Type::Text;
    d.value = value;
    data[key] = d;
    return *this;
}

FormDataBody & FormDataBody::file(const std::string &key, const std::string &fileName, const std::string &filePath, const std::string &mimeType)
{
    DataValue d;
    d.type = DataValue::Type::File;
    d.mimeType = mimeType;
    d.fileName = fileName;
    d.value = filePath;
    data[key] = d;
    return *this;
}

// MARK: - Request
Request::Request(Method method, const std::string &url)
{
    _info = std::make_shared<RequestInfo>();
    _info->method = method;
    _info->url = url;
}

Request * Request::header(const std::string &key, const std::string &value)
{
    _info->headers[key] = value;
    return this;
}

Request * Request::paramBody(std::function<void(ParamBody &body)> maker)
{
    maker(_info->param);
    return this;
}

static void s_setContentType(Request *req, const std::string &type)
{
    req->header("Content-Type", type);
}

Request * Request::rawBody(const std::string &raw, const std::string &contentType)
{
    _info->body.type = RequestBody::Type::raw;
    _info->body.raw = raw;
    s_setContentType(this, contentType);
    return this;
}

Request * Request::xWwwFormUrlencodedBody(std::function<void (XWwwFormUrlencodedBody &)> maker)
{
    _info->body.type = RequestBody::Type::x_www_form_urlencoded;
    maker(_info->body.params);
    s_setContentType(this, "application/x-www-form-urlencoded");
    return this;
}

Request * Request::formDataBody(std::function<void (FormDataBody &)> maker)
{
    _info->body.type = RequestBody::Type::form_data;
    maker(_info->body.formData);
    s_setContentType(this, "multipart/form-data");
    return this;
}

Request * Request::timeout(int32_t seconds)
{
    _info->timeout = seconds;
    return this;
}
Request * Request::redirects(bool isFollowRedirects, int64_t maxRedirects/* = -1*/)
{
    _info->followRedirects = isFollowRedirects;
    _info->maxRedirects = maxRedirects;
    return this;
}
Request * Request::noSignal(bool isNoSignal/* = true*/)
{
    _info->noSignal = isNoSignal;
    return this;
}
Request * Request::auth(const std::string &username, const std::string &password)
{
    _info->auth.username = username;
    _info->auth.password = password;
    return this;
}

Request * Request::sslVerifyHost(bool verify)
{
    _info->sslVerifyHost = verify;
    return this;
}

Request * Request::sslVerifyPeer(bool verify)
{
    _info->sslVerifyPeer = verify;
    return this;
}

Request * Request::caInfoFilePath(const std::string &caInfoFilePath)
{
    _info->caInfoFilePath = caInfoFilePath;
    return this;
}

Request * Request::certPath(const std::string &certPath)
{
    _info->certPath = certPath;
    return this;
}

Request * Request::certType(const std::string &certType)
{
    _info->certType = certType;
    return this;
}
Request * Request::keyPath(const std::string &keyPath)
{
    _info->keyPath = keyPath;
    return this;
}
Request * Request::keyPassword(const std::string &keyPassword)
{
    _info->keyPassword = keyPassword;
    return this;
}
Request * Request::userAgent(const std::string &userAgent)
{
    _info->userAgent = userAgent;
    return this;
}
Request * Request::proxy(const std::string &uriProxy)
{
    _info->uriProxy = uriProxy;
    return this;
}
Request * Request::unixSocketPath(const std::string &unixSocketPath)
{
    _info->unixSocketPath = unixSocketPath;
    return this;
}

Request * Request::host(const std::string &hostName, uint16_t port,
                        const std::string &ip)
{
    return host(hostName, port, std::vector<std::string>{ip});
}

Request * Request::host(const std::string &hostName, uint16_t port,
                        const std::vector<std::string> &ips)
{
    HostResolve h;
    h.host = hostName;
    h.ips = ips;
    h.port = port;
    _info->hosts.insert(h);
    return this;
}

Request * Request::session(const std::shared_ptr<Session> &session)
{
    _session = session;
    return this;
}

Task::Ptr Request::send()
{
    if (auto session = _session.lock())
    {
        return session->send(*this);
    }

    return Requests::sharedSession()->send(*this);
}

Task::Ptr Request::sendAndDownload(const std::string &toFile)
{
    if (auto session = _session.lock())
    {
        return session->sendAndDownload(*this, toFile);
    }

    return Requests::sharedSession()->sendAndDownload(*this, toFile);
}

#define __USING_SHARED_CURL 0

#define __LOCK(m) std::unique_lock<std::mutex> lock(m)
#define __RECURSIVE_LOCK(m) std::unique_lock<std::recursive_mutex> lock(m)
// MARK: - Session
Session::~Session()
{
    _isInDestory = true;

    cancelAllRunningTasks();
    _taskCV.notify_all();

    for (auto &t : _threadList)
    {
        if (t.joinable())
        {
            t.join();
        }
    }
    _threadList.clear();

#if __USING_SHARED_CURL
    if (_curlShared)
    {
        curl_share_cleanup(_curlShared);
        _curlShared = nullptr;
    }
#endif
}

void Session::recordRunningTask(const Task::Ptr &task)
{
    __LOCK(_runningTaskMutex);
    _runningTask[task.get()] = task;
}

void Session::removeRunningTask(const Task::Ptr &task)
{
    __LOCK(_runningTaskMutex);
    _runningTask.erase(task.get());
}

void Session::cancelAllRunningTasks()
{
    __LOCK(_runningTaskMutex);
    for (auto &iter : _runningTask)
    {
        iter.second->cancel();
    }
    _runningTask.clear();
}

static void s_sharedLockFunc(CURL *handle, curl_lock_data data, curl_lock_access access, void *userptr)
{
    std::mutex *mutexs = static_cast<std::mutex *>(userptr);
    mutexs[data].lock();
}

static void s_sharedUnLockFunc(CURL *handle, curl_lock_data data, void *userptr)
{
    std::mutex *mutexs = static_cast<std::mutex *>(userptr);
    mutexs[data].unlock();
}

Session::Session(const std::string &baseUrl)
: _baseUrl(baseUrl), _isInDestory(false), _nextTaskId(1), _maxThreadNum(DefaultThreadNum)
{
#if __USING_SHARED_CURL
    _curlShared = curl_share_init();
    curl_share_setopt(_curlShared, CURLSHOPT_LOCKFUNC, s_sharedLockFunc);
    curl_share_setopt(_curlShared, CURLSHOPT_UNLOCKFUNC, s_sharedUnLockFunc);
    curl_share_setopt(_curlShared, CURLSHOPT_USERDATA, _curlSharedMutex);

    curl_share_setopt(_curlShared, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS);
    curl_share_setopt(_curlShared, CURLSHOPT_SHARE, CURL_LOCK_DATA_SSL_SESSION);
    curl_share_setopt(_curlShared, CURLSHOPT_SHARE, CURL_LOCK_DATA_CONNECT);
#endif
}

void Session::Run(Session *session, uint64_t id)
{
    thread_local CURL *s_t_curl_handler = nullptr;
    if (s_t_curl_handler == nullptr)
    {
        s_t_curl_handler = curl_easy_init();
    }

    while (session->isRunning(id))
    {
        auto task = session->popTask();
        if (task)
        {
#if __USING_SHARED_CURL
            curl_easy_setopt(s_t_curl_handler, CURLOPT_SHARE, session->_curlShared);
#endif
            auto resp = doRequest(task->info(), task->saveFilePath(), s_t_curl_handler, [task](auto progress) {
                if (task->state() == Task::State::Canceled)
                {
                    return Progress::Operation::Stop;
                }

                task->notifyProgress(progress);
                return Progress::Operation::Continue;
            });

            if (resp && resp->isSuccess())
            {
                task->notifySuccess(resp);
            }
            else
            {
                task->notifyFail(resp ? resp->resCode : -1,
                                 resp ? resp->statusCode : -1,
                                 resp);
            }
            auto finish = task->finish();
            if (finish)
            {
                finish(task.get(), resp);
            }
            session->removeRunningTask(task);
        }
        else
        {
            __RECURSIVE_LOCK(session->_taskMutex);
            session->_taskCV.wait(lock);
        }
    }

    curl_easy_cleanup(s_t_curl_handler);
}

void Session::createWorkerIfNeed()
{
    __RECURSIVE_LOCK(_taskMutex);
    while (_workerIds.size() < _maxThreadNum)
    {
        _workerIds.push_back(++_nextWorkerId);
        _threadList.push_back(std::thread(Session::Run, this, _nextWorkerId));
    }
}

void Session::maxThreadNum(size_t num)
{
    _maxThreadNum = num;
    __RECURSIVE_LOCK(_taskMutex);
    if (_workerIds.size() > num)
    {
        _workerIds.resize(num);
    }
}

size_t Session::maxThreadNum() const
{
    return _maxThreadNum;
}

const std::string & Session::baseUrl() const { return _baseUrl; }
Request::Ptr Session::request(Method method, const std::string &path)
{
    auto request = Request::Ptr(new Request(method, path));
    request->session(shared_from_this());
    return request;
}

bool Session::isRunning(uint64_t id)
{
    if (_isInDestory) return false;
    __RECURSIVE_LOCK(_taskMutex);
    return std::any_of(_workerIds.begin(), _workerIds.end(), [&](uint64_t worker) {
        return worker == id;
    });
}

Task::Ptr Session::popTask()
{
    __RECURSIVE_LOCK(_taskMutex);
    if (_taskQueue.empty()) return nullptr;

    auto task = _taskQueue.front();
    recordRunningTask(task);
    _taskQueue.pop();
    return task;
}

static inline bool s_isRelativePath(const std::string &path)
{
    if (path.empty()) return false;
    return path.front() == '/';
}

Task::Ptr Session::addTask(const Request &request, const std::string &toFile)
{
    if (_isInDestory) return nullptr;

    __RECURSIVE_LOCK(_taskMutex);
    createWorkerIfNeed();

    const auto &info = *request._info;
    auto task = Task::Ptr(new Task(++_nextTaskId, info, toFile));

    if (!_baseUrl.empty() && s_isRelativePath(info.url))
    {
        task->_info->url = _baseUrl + task->_info->url;
    }

    _taskQueue.push(task);
    _taskCV.notify_one();
    return task;
}

Task::Ptr Session::send(const Request &request)
{
    return sendAndDownload(request, "");
}

Task::Ptr Session::sendAndDownload(const Request &request, const std::string &toFile)
{
    return addTask(request, toFile);
}

// MARK: - Requests
Session * Requests::sharedSession()
{
    static Session *s_shared = nullptr;
    if (s_shared == nullptr)
    {
        s_shared = new Session("");
    }
    return s_shared;
}

void Requests::init()
{
    curl_global_init(CURL_GLOBAL_DEFAULT);
    sharedSession(); // init
}

void Requests::destory()
{
    curl_global_cleanup();
}

Session::Ptr Requests::session(const std::string &baseUrl)
{
    return Session::Ptr(new Session(baseUrl));
}

Request::Ptr Requests::request(Method method, const std::string &url)
{
    return Request::Ptr(new Request(method, url));
}

// MARK: - Task
Task::~Task()
{
    cancel();
}

Task::Task(size_t taskId, const RequestInfo &info, const std::string &toFile) :
_saveToFilePath(toFile), _info(std::make_shared<RequestInfo>(info)), _taskId(taskId)
{
}

size_t Task::taskId() const
{
    return _taskId;
}

Task::State Task::state() const
{
    __RECURSIVE_LOCK(_mutex);
    return _state;
}

bool Task::changeState(State state)
{
    __RECURSIVE_LOCK(_mutex);
    const bool s_stateTable[][State::Last] = {
    //   Init, Pending, Success, Fail, Canceled
        { 0, 1, 1, 1, 1 }, // Init
        { 1, 0, 1, 1, 1 }, // Pending
        { 0, 0, 0, 0, 0 }, // Success
        { 1, 1, 1, 0, 0 }, // Fail
        { 1, 1, 1, 1, 0 }, // Canceled
    };
    if (!s_stateTable[_state][state]) return false;

    _state = state;
    _cv.notify_all();
    return true;
}

void Task::wait() const
{
    __RECURSIVE_LOCK(_mutex);
    _cv.wait(lock, [=] {
        return (_state == State::Success ||
                _state == State::Fail ||
                _state == State::Canceled);
    });
}

bool Task::cancel()
{
    return changeState(State::Canceled);
}

Task * Task::onProgress(const ProgressHandler &handler)
{
    __RECURSIVE_LOCK(_mutex);
    _progress = handler;
    return this;
}

Task * Task::onFail(const FailHandler &handler)
{
    __RECURSIVE_LOCK(_mutex);
    _fail = handler;
    if (_state == State::Fail && handler)
    {
        handler(this, _resCode, _statusCode, _response);
    }
    return this;
}

Task * Task::onSuccess(const SuccessHandler &handler)
{
    __RECURSIVE_LOCK(_mutex);
    _success = handler;
    if (_state == State::Success && handler)
    {
        handler(this, _response);
    }
    return this;
}

Task * Task::onFinish(const FinishHandler &handler)
{
    __RECURSIVE_LOCK(_mutex);
    _finish = handler;
    if ((_state == State::Fail || _state == State::Success) && handler)
    {
        handler(this, _response);
    }
    return this;
}

const Task::ProgressHandler & Task::progress() const
{
    __RECURSIVE_LOCK(_mutex);
    return _progress;
}

const Task::FailHandler & Task::fail() const
{
    __RECURSIVE_LOCK(_mutex);
    return _fail;
}

const Task::SuccessHandler & Task::success() const
{
    __RECURSIVE_LOCK(_mutex);
    return _success;
}

const Task::FinishHandler & Task::finish() const
{
    __RECURSIVE_LOCK(_mutex);
    return _finish;
}

void Task::notifyFail(int32_t resCode, int64_t statusCode, const ResponseInfo::Ptr &respInfo)
{
    __RECURSIVE_LOCK(_mutex);
    if (!changeState(State::Fail))
    {
        return;
    }

    _resCode = resCode;
    _statusCode = statusCode;
    _response = respInfo;
    if (_fail)
    {
        _fail(this, _resCode, _statusCode, _response);
    }
}

void Task::notifySuccess(const ResponseInfo::Ptr &respInfo)
{
    __RECURSIVE_LOCK(_mutex);
    if (!changeState(State::Success))
    {
        return;
    }

    _response = respInfo;
    if (_success)
    {
        _success(this, respInfo);
    }
}

void Task::notifyProgress(const Progress &progress)
{
    __RECURSIVE_LOCK(_mutex);
    changeState(State::Pending);

    if (_progress)
    {
        _progress(this, progress);
    }
}

const RequestInfo & Task::info() const
{
    __RECURSIVE_LOCK(_mutex);
    return *_info;
}

const std::string & Task::saveFilePath() const
{
    __RECURSIVE_LOCK(_mutex);
    return _saveToFilePath;
}

namespace
{
    template <class ContainerT>
    static inline std::string s_join(const ContainerT &container,
                                     const std::string &separator,
                                     const std::function<std::string (typename ContainerT::const_iterator iter)> &toString)
    {
        std::string ret;
        for (auto iter = container.begin(); iter != container.end(); ++iter)
        {
            if (!ret.empty()) ret += separator;
            ret += toString(iter);
        }
        return ret;
    }

    static inline std::string s_join(const std::vector<std::string> &container, const std::string &separator)
    {
        return s_join(container, separator, [](auto iter) { return *iter; });
    }

    static inline std::string & s_ltrim(std::string& s)
    {
        s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](char c) {return !isspace(c);}));
        return s;
    }

    static inline std::string & s_rtrim(std::string& s)
    {
        s.erase(std::find_if(s.rbegin(), s.rend(), [](char c) {return !isspace(c);}).base(), s.end());
        return s;
    }

    static inline std::string & s_trim(std::string& s)
    {
        return s_ltrim(s_rtrim(s));
    }

    struct __SListObj
    {
        curl_slist *slist = nullptr;
        virtual ~__SListObj()
        {
            if (slist)
            {
                curl_slist_free_all(slist);
                slist = nullptr;
            }
        }
    };

    struct __Header : public __SListObj
    {
        __Header(CURL *handler, const RequestInfo &info)
        {
            if (info.headers.empty()) return;

            for (auto &iter : info.headers)
            {
                std::string format = iter.first + ": " + iter.second;
                slist = curl_slist_append(slist, format.c_str());
            }

            curl_easy_setopt(handler, CURLOPT_HTTPHEADER, slist);
        }
    };

    struct __Host : public __SListObj
    {
        __Host(CURL *handler, const RequestInfo &info)
        {
            if (info.hosts.empty()) return;

            for (auto &iter : info.hosts)
            {
                if (iter.ips.empty()) continue;
                auto ips = s_join(iter.ips, ",");
                std::string format = iter.host + ":" + std::to_string(iter.port) + ":" + ips;
                slist = curl_slist_append(slist, format.c_str());
            }

            curl_easy_setopt(handler, CURLOPT_RESOLVE, slist);
        }
    };

    struct __Auth
    {
        std::string authData;
        __Auth(CURL *handler, const RequestInfo &info)
        {
            if (info.auth.username.empty()) return;

            authData = info.auth.username + ":" + info.auth.password;
            curl_easy_setopt(handler, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
            curl_easy_setopt(handler, CURLOPT_USERPWD, authData.c_str());
        }
    };

    struct __Escape
    {
        char *str = nullptr;
        __Escape(CURL *handler, const std::string &target)
        {
            str = curl_easy_escape(handler, target.c_str(), static_cast<int>(target.size()));
        }
        ~__Escape()
        {
            if (str)
            {
                curl_free(str);
            }
        }
    };

    static std::string s_formParam(CURL *handler, const ParamBody &params)
    {
        return s_join(params.data, "&", [&](auto iter) {
            auto value = __Escape(handler, iter->second);
            return iter->first + "=" + std::string(value.str);
        });
    }

    struct __Body
    {
        std::string raw;
        curl_mime *form = nullptr;

        __Body(CURL *handler, const RequestInfo &info)
        {
            if (info.method != Method::POST) return;

            curl_easy_setopt(handler, CURLOPT_POST, 1L);
            if (info.body.type == RequestBody::Type::form_data)
            {
                if (info.body.formData.data.empty()) return;

                form = curl_mime_init(handler);
                for (auto &iter : info.body.formData.data)
                {
                    auto field = curl_mime_addpart(form);
                    curl_mime_name(field, iter.first.c_str());
                    auto &value = iter.second;
                    if (value.type == FormDataBody::DataValue::Type::File)
                    {
                        curl_mime_filedata(field, value.value.c_str());
                    }
                    else
                    {
                        curl_mime_data(field, value.value.c_str(), value.value.size());
                    }
                    if (!value.mimeType.empty())
                    {
                        curl_mime_type(field, value.mimeType.c_str());
                    }
                    if (!value.fileName.empty())
                    {
                        curl_mime_filename(field, value.fileName.c_str());
                    }
                }
                curl_easy_setopt(handler, CURLOPT_MIMEPOST, form);
                return;
            }

            const std::string *tmpRaw = &(info.body.raw);
            if (info.body.type == RequestBody::Type::x_www_form_urlencoded)
            {
                raw = s_formParam(handler, info.body.params);
                tmpRaw = &raw;
            }

            curl_easy_setopt(handler, CURLOPT_POSTFIELDS, tmpRaw->c_str());
            curl_easy_setopt(handler, CURLOPT_POSTFIELDSIZE, tmpRaw->size());
        }
        ~__Body()
        {
            if (form)
            {
                curl_mime_free(form);
                form = nullptr;
            }
        }
    };

    // response
    struct __Response
    {
        ResponseInfo::Ptr resp;

        std::string saveToFilePath;
        FILE *saveToFile = nullptr;
        const Progress::Handler &progress;

        size_t writeBody(void *data, size_t size, size_t nmemb)
        {
            if (size == 0 || nmemb == 0) return 0;

            if (saveToFile)
            {
                return fwrite(data, size, nmemb, saveToFile);
            }

            size *= nmemb;
            resp->body.append(static_cast<const char *>(data), size);
            return size;
        }

        size_t writeHeader(void *data, size_t size, size_t nmemb)
        {
            size *= nmemb;
            std::string header(static_cast<const char*>(data), size);
            size_t seperator = header.find_first_of(':');
            if (std::string::npos == seperator)
            {
                s_trim(header);
                resp->headers[header] = "";
            }
            else
            {
                std::string key = header.substr(0, seperator);
                s_trim(key);
                std::string value = header.substr(seperator + 1);
                s_trim(value);
                resp->headers[key] = value;
            }

            return size;
        }

        void onEnd(CURL *handler)
        {
            curl_easy_getinfo(handler, CURLINFO_RESPONSE_CODE, &resp->statusCode);
            curl_easy_getinfo(handler, CURLINFO_HTTP_VERSION, &resp->httpVersion);

            curl_easy_getinfo(handler, CURLINFO_TOTAL_TIME, &resp->statistics.totalTime);
            curl_easy_getinfo(handler, CURLINFO_NAMELOOKUP_TIME, &resp->statistics.nameLookupTime);
            curl_easy_getinfo(handler, CURLINFO_CONNECT_TIME, &resp->statistics.connectTime);
            curl_easy_getinfo(handler, CURLINFO_APPCONNECT_TIME, &resp->statistics.appConnectTime);
            curl_easy_getinfo(handler, CURLINFO_PRETRANSFER_TIME, &resp->statistics.preTransferTime);
            curl_easy_getinfo(handler, CURLINFO_STARTTRANSFER_TIME, &resp->statistics.startTransferTime);
            curl_easy_getinfo(handler, CURLINFO_REDIRECT_TIME, &resp->statistics.redirectTime);
            curl_easy_getinfo(handler, CURLINFO_REDIRECT_COUNT, &resp->statistics.redirectCount);

            if (!resp->isSuccess() && saveToFile)
            {
                closeFile();
                remove(saveToFilePath.c_str());
            }
        }

        void closeFile()
        {
            if (saveToFile)
            {
                fclose(saveToFile);
                saveToFile = nullptr;
            }
        }

        __Response(const Progress::Handler &handler, const std::string &toFile) : progress(handler)
        {
            resp = std::make_shared<ResponseInfo>();
            if (!toFile.empty())
            {
                saveToFilePath = toFile;
                saveToFile = fopen(toFile.c_str(), "wb");
                resp->body = toFile;
            }
        }
        ~__Response()
        {
            closeFile();
        }
    };

    static int32_t s_response_progress(void *userdata, curl_off_t dltotal, curl_off_t dlnow,
                                   curl_off_t ultotal, curl_off_t ulnow)
    {
        __Response *resp = static_cast<__Response *>(userdata);
        if (resp->progress)
        {
            Progress p;
            p.download.total = dltotal;
            p.download.current = dlnow;
            p.upload.total = ultotal;
            p.upload.current = ulnow;
            return resp->progress(p);
        }
        return 0;
    }

    static size_t s_response_body(void *data, size_t size, size_t nmemb, void *userdata)
    {
        return static_cast<__Response *>(userdata)->writeBody(data, size, nmemb);
    }

    static size_t s_response_header(void *data, size_t size, size_t nmemb, void *userdata)
    {
        return static_cast<__Response *>(userdata)->writeHeader(data, size, nmemb);
    }

    ResponseInfo::Ptr doRequest(const RequestInfo &info, const std::string &toFile,
                                CURL *curlHandler, const Progress::Handler &progressHandler)
    {
        curl_easy_reset(curlHandler);

        __Response resp(progressHandler, toFile);

        auto url = info.url;
        if (info.method == Method::GET)
        {
            auto params = s_formParam(curlHandler, info.param);
            if (!params.empty())
            {
                url += "?" + params;
            }
        }

        curl_easy_setopt(curlHandler, CURLOPT_URL, url.c_str());
        // headers
        __Header header(curlHandler, info);
        __Host hosts(curlHandler, info);
        if (!info.userAgent.empty())
        {
            curl_easy_setopt(curlHandler, CURLOPT_USERAGENT, info.userAgent.c_str());
        }

        // body
        __Body body(curlHandler, info);

        // config
        // config - default
        curl_easy_setopt(curlHandler, CURLOPT_FAILONERROR, 1L);

        // config - custom
        __Auth auth(curlHandler, info);

        if (info.timeout > 0)
        {
            curl_easy_setopt(curlHandler, CURLOPT_TIMEOUT, info.timeout);
            curl_easy_setopt(curlHandler, CURLOPT_NOSIGNAL, 1L);
        }

        if (info.noSignal)
        {
            curl_easy_setopt(curlHandler, CURLOPT_NOSIGNAL, 1L);
        }

        if (info.followRedirects)
        {
            curl_easy_setopt(curlHandler, CURLOPT_FOLLOWLOCATION, 1L);
            curl_easy_setopt(curlHandler, CURLOPT_MAXREDIRS, info.maxRedirects);
        }

        curl_easy_setopt(curlHandler, CURLOPT_SSL_VERIFYPEER, info.sslVerifyPeer ? 0L : 1L);
        curl_easy_setopt(curlHandler, CURLOPT_SSL_VERIFYHOST, info.sslVerifyHost ? 0L : 2L);
        if (!info.caInfoFilePath.empty())
        {
            curl_easy_setopt(curlHandler, CURLOPT_CAINFO, info.caInfoFilePath.c_str());
        }

        if (!info.certPath.empty())
        {
            curl_easy_setopt(curlHandler, CURLOPT_SSLCERT, info.certPath.c_str());
        }

        if (!info.certType.empty())
        {
            curl_easy_setopt(curlHandler, CURLOPT_SSLCERTTYPE, info.certType.c_str());
        }

        if (!info.keyPath.empty())
        {
            curl_easy_setopt(curlHandler, CURLOPT_SSLKEY, info.keyPath.c_str());
        }

        if (!info.keyPassword.empty())
        {
            curl_easy_setopt(curlHandler, CURLOPT_KEYPASSWD, info.keyPassword.c_str());
        }

        if (!info.uriProxy.empty())
        {
            curl_easy_setopt(curlHandler, CURLOPT_PROXY, info.uriProxy.c_str());
            curl_easy_setopt(curlHandler, CURLOPT_HTTPPROXYTUNNEL, 1L);
        }

        if (!info.unixSocketPath.empty())
        {
            curl_easy_setopt(curlHandler, CURLOPT_UNIX_SOCKET_PATH, info.unixSocketPath.c_str());
        }

        // response
        if (progressHandler)
        {
            curl_easy_setopt(curlHandler, CURLOPT_NOPROGRESS, 0L);
            curl_easy_setopt(curlHandler, CURLOPT_XFERINFOFUNCTION, s_response_progress);
            curl_easy_setopt(curlHandler, CURLOPT_XFERINFODATA, &resp);
        }

        curl_easy_setopt(curlHandler, CURLOPT_WRITEFUNCTION, s_response_body);
        curl_easy_setopt(curlHandler, CURLOPT_WRITEDATA, &resp);

        curl_easy_setopt(curlHandler, CURLOPT_HEADERFUNCTION, s_response_header);
        curl_easy_setopt(curlHandler, CURLOPT_HEADERDATA, &resp);

        resp.resp->resCode = curl_easy_perform(curlHandler);
        resp.onEnd(curlHandler);

        curl_easy_reset(curlHandler);
        return resp.resp;
    }
}
__NS_END
