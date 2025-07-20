#include <iostream>
#include <cstring>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <signal.h>

#include <event2/event.h>
#include <event2/bufferevent.h>
#include <cstring>
#include <iostream>
#include <string>

#include <event2/event.h>
#include <event2/bufferevent.h>
#include <cstring>
#include <iostream>
#include <string>
#include <netinet/in.h>

#include <event2/event.h>
#include <event2/http.h>

#include <unistd.h>
#include <sys/un.h>
#include <event2/keyvalq_struct.h>
#include <sys/stat.h>

#include <dirent.h>
#include <sys/types.h>
#include <fcntl.h>

#define use_socket
#define use_event_buff

namespace tcpClient
{
    enum class ClientState
    {
        CONNECTING, // 正在连接 [新增状态]
        CONNECTED,  // 连接成功
        WRITING,    // 正在写数据
        READING,    // 正在读数据
        CLOSING     // 正在关闭 [新增状态]
    };

    struct ClientContext
    {
        ClientState state = ClientState::CONNECTING; // 初始状态修正
        bufferevent *bev = nullptr;
        std::string sendData; // 改用string管理发送数据
        std::string recvBuffer;
        event_base *base = nullptr;
    };

    // --------------- 回调函数优化 ---------------
    void client_event_cb(bufferevent *bev, short events, void *arg)
    {
        ClientContext *ctx = static_cast<ClientContext *>(arg);
        std::cout << "Event: " << events << std::endl;

        if (events & BEV_EVENT_CONNECTED)
        {
            std::cout << "Connected to server" << std::endl;
            ctx->state = ClientState::CONNECTED;

            // 连接成功后直接触发首次写入
            bufferevent_trigger(bev, EV_WRITE, 0);
        }
        else if (events & BEV_EVENT_EOF)
        {
            std::cout << "Connection closed by server" << std::endl;
            if (ctx->recvBuffer.size() > 0)
            {
                std::cout << "Final data received: " << ctx->recvBuffer << std::endl;
            }
            ctx->state = ClientState::CLOSING;
            bufferevent_free(bev);
            delete ctx;
        }
        else if (events & BEV_EVENT_ERROR)
        {
            std::cerr << "Socket error: " << evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()) << std::endl;
            bufferevent_free(bev);
            delete ctx;
        }
        else if (events & BEV_EVENT_TIMEOUT)
        {
            std::cerr << (events & BEV_EVENT_READING ? "Read" : "Write") << " timeout" << std::endl;
            bufferevent_free(bev);
            delete ctx;
        }
    }

    void client_write_cb(bufferevent *bev, void *arg)
    {
        ClientContext *ctx = static_cast<ClientContext *>(arg);

        if (ctx->state == ClientState::CONNECTED)
        {
            // 首次发送数据
            std::string msg = "CLIENT: " + ctx->sendData;
            bufferevent_write(bev, msg.c_str(), msg.size());
            std::cout << "Data sent: " << msg << std::endl;
            ctx->state = ClientState::WRITING;

            // 准备接收响应
            bufferevent_enable(bev, EV_READ);
        }
        else if (ctx->state == ClientState::WRITING)
        {
            // 写入完成后的状态转换
            ctx->state = ClientState::READING;
        }
    }

    void client_read_cb(bufferevent *bev, void *arg)
    {
        ClientContext *ctx = static_cast<ClientContext *>(arg);
        char buf[1024];

        while (true)
        {
            int n = bufferevent_read(bev, buf, sizeof(buf) - 1);
            if (n <= 0)
                break;

            buf[n] = '\0';
            ctx->recvBuffer.append(buf, n);
            std::cout << "Partial data: " << buf << std::endl;
        }

        // 检测到完整消息（示例：按换行符分割）
        size_t pos;
        while ((pos = ctx->recvBuffer.find('c')) != std::string::npos)
        {
            std::string message = ctx->recvBuffer.substr(0, pos);
            ctx->recvBuffer.erase(0, pos + 1);
            std::cout << "完整消息: " << message << std::endl;

            // 收到完整消息后关闭连接（根据业务逻辑调整）
            ctx->state = ClientState::CLOSING;
            bufferevent_disable(bev, EV_READ | EV_WRITE);
            bufferevent_free(bev);
            delete ctx;
            return; // 资源已释放，立即退出
        }
    }

    // --------------- 主函数优化 ---------------
    int test(const std::string &mode)
    {
        event_base *base = event_base_new();
        if (!base)
            return -1;

        // 创建非阻塞socket
        bufferevent *bev = bufferevent_socket_new(
            base,
            -1,
            BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
        if (!bev)
        {
            event_base_free(base);
            return -1;
        }

        // 配置服务器地址
        sockaddr_in sin = {0};
        sin.sin_family = AF_INET;
        sin.sin_port = htons(8000);
        evutil_inet_pton(AF_INET, "192.168.1.2", &sin.sin_addr.s_addr);

        // 初始化上下文
        ClientContext *ctx = new ClientContext();
        ctx->bev = bev;
        ctx->base = base;
        ctx->sendData = (mode == "read") ? "READ_REQUEST" : "WRITE_REQUEST";
        ctx->state = ClientState::CONNECTING;

        // 设置回调
        bufferevent_setcb(bev, client_read_cb, client_write_cb, client_event_cb, ctx);

        // 设置超时（读写各3秒）
        timeval tv = {10, 0};
        bufferevent_set_timeouts(bev, &tv, &tv);

        // 启用写事件（连接建立后触发）
        bufferevent_enable(bev, EV_WRITE);

        // 发起连接
        if (bufferevent_socket_connect(bev, (sockaddr *)&sin, sizeof(sin)))
        {
            std::cerr << "Connection failed" << std::endl;
            bufferevent_free(bev);
            delete ctx;
            event_base_free(base);
            return -1;
        }

        // 启动事件循环
        event_base_dispatch(base);
        event_base_free(base);
        std::cout << "Client terminated" << std::endl;
        return 0;
    }
}

namespace tcpServer
{

    void close_client(event *ev, evutil_socket_t fd)
    {
        if (ev)
            event_free(ev);
        if (fd >= 0)
            evutil_closesocket(fd);
    }

    void client_cb(evutil_socket_t fd, short events, void *arg)
    {
        event *ev = (event *)arg;

        if (events & EV_TIMEOUT)
        {
            std::cout << "Connection timeout" << std::endl;
            close_client(ev, fd);
            return;
        }

        char buf[1024] = {0};
        int len = ::recv(fd, buf, sizeof(buf) - 1, 0);

        if (len > 0)
        {
            std::cout << "Received: " << buf << std::endl;
            if (::send(fd, "ok", 2, 0) < 0 && errno != EAGAIN)
            {
                std::cerr << "send error: " << strerror(errno) << std::endl;
            }
        }
        else if (len == 0)
        {
            std::cout << "Client disconnected" << std::endl;
            close_client(ev, fd);
        }
        else
        {
            if (errno != EAGAIN)
            {
                std::cerr << "recv error: " << strerror(errno) << std::endl;
                close_client(ev, fd);
            }
        }
    }
    void event_cb(bufferevent *be, short events, void *)
    {

        if (events & BEV_EVENT_TIMEOUT)
        {
            if (events & BEV_EVENT_READING)
            {
                std::cout << "BEV_EVENT_READING TIMEOUT" << std::endl;
            }
            else if (events & BEV_EVENT_WRITING)
            {
                std::cout << "BEV_EVENT_WRITING TIMEOUT" << std::endl;
            }
        }
        else if (events & BEV_EVENT_EOF)
        {
            std::cout << "BEV_EVENT_EOF: Client disconnected" << std::endl;
        }
        else if (events & BEV_EVENT_ERROR)
        {
            std::cerr << "BEV_EVENT_ERROR: " << evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()) << std::endl;
        }
        else
        {
            std::cout << "OTHERS: " << events << std::endl;
        }
        bufferevent_free(be);
    }
    void write_cb(bufferevent *, void *)
    {
        std::cout << "[W]" << std::endl;
    }

    void read_cb(bufferevent *be, void *)
    {
        char data[1024] = {0};
        // 读取输入缓冲数据
        int len = bufferevent_read(be, data, sizeof(data) - 1);
        std::cout << "[" << data << "]" << std::endl;
        if (len <= 0)
            return;
        if (strstr(data, "quit") != NULL)
        {
            std::cout << "quit";
            // 退出并关闭socket BEV_OPT_CLOSE_ON_FREE
            bufferevent_free(be);
        }
        // 发送数据 写入到输出缓冲
        bufferevent_write(be, "OK", 3);

        // struct evbuffer *input = bufferevent_get_input(be);
        // struct evbuffer *output = bufferevent_get_output(be);

        // // 将接收到的数据原样发回
        // evbuffer_add_buffer(output, input);
        // printf("Echoed %zd bytes\n", evbuffer_get_length(input));
    }

#ifdef use_socket
    void accept_cb(evutil_socket_t listen_fd, short, void *arg)
#else
    void accept_cb(evconnlistener *listener, evutil_socket_t clientFd, sockaddr *sa, int socklen, void *arg)
#endif
    {
        event_base *base = (event_base *)arg;
        timeval timeout = {10, 0};
#ifdef use_socket
        sockaddr_in sinaddr;
        socklen_t size = sizeof(sinaddr);
        int clientFd = ::accept(listen_fd, (sockaddr *)&sinaddr, &size);

        if (clientFd < 0)
        {
            if (errno != EAGAIN && errno != EWOULDBLOCK)
            {
                std::cerr << "accept error: " << strerror(errno) << std::endl;
            }
            return;
        }

        evutil_make_socket_nonblocking(clientFd);
        sockaddr_in *sin = &sinaddr;
#else
        sockaddr_in *sin = (sockaddr_in *)sa;
#endif
        char ip[32] = {0};
        evutil_inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip) - 1);
        std::cout << "Client connected from: " << ip << std::endl;
#ifdef use_event_buff
        bufferevent *bev = bufferevent_socket_new(base, clientFd, BEV_OPT_CLOSE_ON_FREE);
        bufferevent_enable(bev, EV_READ | EV_WRITE);

        // 读低水位（low）	输入缓冲 ≥ low → 触发读回调	回调不触发，数据滞留缓冲
        // 读高水位（high）	输入缓冲 ≥ high → 暂停读取	无影响，持续读取直至超限
        // 写低水位（low）	输出缓冲 ≤ low → 触发写回调	回调不触发，需手动监控
        // 写高水位（high）	仅用于过滤型 bufferevent 的流量控制	普通场景无效

        bufferevent_setwatermark(bev, EV_READ, 5, 10);
        bufferevent_setwatermark(bev, EV_WRITE, 5, 10); // 高水位写无效
        bufferevent_set_timeouts(bev, &timeout, 0);

        bufferevent_setcb(bev, read_cb, write_cb, event_cb, base);

#else
        event *ev = event_new(base, clientFd, EV_READ | EV_PERSIST, client_cb, event_self_cbarg());

        if (!ev)
        {
            std::cerr << "Failed to create client event" << std::endl;
            evutil_closesocket(clientFd);
            return;
        }

        if (event_add(ev, &timeout) != 0)
        {
            std::cerr << "Failed to add client event" << std::endl;
            close_client(ev, clientFd);
        }
#endif
    }

    void error_cb(evconnlistener *, void *arg)
    {
        event_base *base = (event_base *)arg;
        std::cerr << "Listener error: " << evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()) << std::endl;
        timeval timeout = {3, 0};
        event_base_loopexit(base, &timeout);
    }

    int test()
    {
        event_base *base = event_base_new();
        if (!base)
        {
            return -1;
        }
#ifdef use_socket
        int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (listen_fd <= 0)
        {
            std::cerr << "socket error: " << strerror(errno) << std::endl;
            return -1;
        }

        evutil_make_socket_nonblocking(listen_fd);
        evutil_make_listen_socket_reuseable(listen_fd);

        sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_port = htons(8000);
        if (::bind(listen_fd, (sockaddr *)&sin, sizeof(sin)) != 0)
        {
            std::cerr << "bind error: " << strerror(errno) << std::endl;
            evutil_closesocket(listen_fd);
            return -1;
        }

        if (::listen(listen_fd, 128) != 0)
        {
            std::cerr << "listen error: " << strerror(errno) << std::endl;
            evutil_closesocket(listen_fd);
            return -1;
        }

        event *ev = event_new(base, listen_fd, EV_READ | EV_PERSIST, accept_cb, base);
        if (!ev || event_add(ev, NULL) != 0)
        {
            std::cerr << "Failed to create listener event" << std::endl;
            if (ev)
                event_free(ev);
            evutil_closesocket(listen_fd);
            return -1;
        }
#else
        sockaddr_in sin = {0};
        sin.sin_family = AF_INET;
        sin.sin_port = htons(8000);
        // 封装了 socket bind listen event_new event_add
        evconnlistener *listener = evconnlistener_new_bind(
            base, accept_cb, base,
            LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE,
            -1, (sockaddr *)&sin, sizeof(sin));

        if (!listener)
        {
            std::cerr << "Failed to create listener: "
                      << evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR())
                      << std::endl;
            event_base_free(base);
            return -1;
        }
        evconnlistener_set_error_cb(listener, error_cb);
#endif

        std::cout << "Server started on port 8000..." << std::endl;
        event_base_dispatch(base);

#ifdef use_socket
        event_free(ev);
        evutil_closesocket(listen_fd);
#else
        evconnlistener_free(listener);
#endif

        return 0;
    }

} // namespace tcpServer

namespace httpServer
{

    char uri_root[512]; ///< 服务器根URI（用于目录列表中的链接）

    /// 内容类型映射表
    static const struct table_entry
    {
        const char *extension;    ///< 文件扩展名
        const char *content_type; ///< MIME类型
    } content_type_table[] = {
        {"txt", "text/plain"},
        {"c", "text/plain"},
        {"h", "text/plain"},
        {"html", "text/html"},
        {"htm", "text/htm"},
        {"css", "text/css"},
        {"gif", "image/gif"},
        {"jpg", "image/jpeg"},
        {"jpeg", "image/jpeg"},
        {"png", "image/png"},
        {"pdf", "application/pdf"},
        {"ps", "application/postscript"},
        {NULL, NULL},
    };

    /// 服务器配置选项
    struct options
    {
        int port;             ///< 监听端口
        int verbose;          ///< 详细输出模式
        int unlink;           ///< 是否删除已存在的Unix套接字
        const char *unixsock; ///< Unix域套接字路径
        const char *docroot;  ///< 文档根目录
    };

    /**
     * @brief 根据文件路径猜测内容类型
     * @param path 文件路径
     * @return 对应的MIME类型字符串
     */
    static const char *guess_content_type(const char *path)
    {
        const char *last_period, *extension;
        const struct table_entry *ent;

        last_period = strrchr(path, '.');
        if (!last_period || strchr(last_period, '/'))
            goto not_found; // 没有扩展名

        extension = last_period + 1;
        for (ent = &content_type_table[0]; ent->extension; ++ent)
        {
            if (!evutil_ascii_strcasecmp(ent->extension, extension))
                return ent->content_type;
        }

    not_found:
        return "application/misc";
    }

    /**
     * @brief 请求调试回调函数
     * @param req HTTP请求对象
     * @param arg 用户自定义参数
     *
     * 处理所有发送到/dump路径的请求，将请求详情输出到控制台并返回200 OK
     */
    static void dump_request_cb(struct evhttp_request *req, void *arg)
    {
        const char *cmdtype;

        // 解析请求方法
        switch (evhttp_request_get_command(req))
        {
        case EVHTTP_REQ_GET:
            cmdtype = "GET";
            break;
        case EVHTTP_REQ_POST:
            cmdtype = "POST";
            break;
        case EVHTTP_REQ_HEAD:
            cmdtype = "HEAD";
            break;
        case EVHTTP_REQ_PUT:
            cmdtype = "PUT";
            break;
        case EVHTTP_REQ_DELETE:
            cmdtype = "DELETE";
            break;
        case EVHTTP_REQ_OPTIONS:
            cmdtype = "OPTIONS";
            break;
        case EVHTTP_REQ_TRACE:
            cmdtype = "TRACE";
            break;
        case EVHTTP_REQ_CONNECT:
            cmdtype = "CONNECT";
            break;
        case EVHTTP_REQ_PATCH:
            cmdtype = "PATCH";
            break;
        default:
            cmdtype = "unknown";
            break;
        }

        printf("Received a %s request for %s\nHeaders:\n",
               cmdtype, evhttp_request_get_uri(req));

        // 打印请求头
        evkeyvalq *headers = evhttp_request_get_input_headers(req);
        for (evkeyval *header = headers->tqh_first; header;
             header = header->next.tqe_next)
        {
            printf("  %s: %s\n", header->key, header->value);
        }

        // 打印请求体
        evbuffer *buf = evhttp_request_get_input_buffer(req);
        puts("Input data: <<<");
        while (evbuffer_get_length(buf))
        {
            int n;
            char cbuf[128];
            n = evbuffer_remove(buf, cbuf, sizeof(cbuf));
            if (n > 0)
                (void)fwrite(cbuf, 1, n, stdout);
        }
        puts(">>>");

        // 发送简单响应
        evhttp_send_reply(req, 200, "OK", NULL);
    }

    /**
     * @brief 主请求处理回调
     * @param req HTTP请求对象
     * @param arg 用户自定义参数（指向options结构体的指针）
     *
     * 处理所有未匹配特定路径的请求，提供静态文件服务和目录列表功能
     */
    static void send_document_cb(struct evhttp_request *req, void *arg)
    {
        evbuffer *evb = NULL;
        options *opt = (options *)arg;
        const char *uri = evhttp_request_get_uri(req);

        char *whole_path = NULL;
        size_t len;
        int fd = -1;
        struct stat st;

        // 非GET请求转发到调试处理器
        if (evhttp_request_get_command(req) != EVHTTP_REQ_GET)
        {
            dump_request_cb(req, arg);
            return;
        }

        printf("Got a GET request for <%s>\n", uri);

        // 解析URI
        evhttp_uri *decoded = evhttp_uri_parse(uri);
        if (!decoded)
        {
            printf("Invalid URI. Sending BADREQUEST\n");
            evhttp_send_error(req, HTTP_BADREQUEST, 0);
            return;
        }

        // 获取URI路径
        const char *path = evhttp_uri_get_path(decoded);
        if (!path)
            path = "/";

        // 解码路径
        char *decoded_path = evhttp_uridecode(path, 0, NULL);
        if (decoded_path == NULL)
            goto err;

        // 安全防护：拒绝包含".."的路径
        if (strstr(decoded_path, ".."))
            goto err;

        // 构建完整文件路径: docroot + decoded_path
        len = strlen(decoded_path) + strlen(opt->docroot) + 2;
        whole_path = (char *)malloc(len);
        if (!whole_path)
        {
            perror("malloc");
            goto err;
        }
        evutil_snprintf(whole_path, len, "%s/%s", opt->docroot, decoded_path);

        // 检查文件是否存在
        if (stat(whole_path, &st) < 0)
        {
            perror("stat");
            goto err;
        }

        // 创建输出缓冲区
        evb = evbuffer_new();

        // 处理目录请求
        if (S_ISDIR(st.st_mode))
        {
            DIR *d;
            struct dirent *ent;
            const char *trailing_slash = "";

            // 确保目录路径以'/'结尾
            if (!strlen(path) || path[strlen(path) - 1] != '/')
                trailing_slash = "/";

            // 打开目录
            if (!(d = opendir(whole_path)))
                goto err;

            // 生成HTML目录列表
            evbuffer_add_printf(evb,
                                "<!DOCTYPE html>\n"
                                "<html>\n"
                                " <head>\n"
                                "  <meta charset='utf-8'>\n"
                                "  <title>%s</title>\n"
                                "  <base href='%s%s'>\n"
                                " </head>\n"
                                " <body>\n"
                                "  <h1>%s</h1>\n"
                                "  <ul>\n",
                                decoded_path, // 注意：实际应用中应对HTML特殊字符进行转义
                                path,
                                trailing_slash,
                                decoded_path);

            // 遍历目录项
            while ((ent = readdir(d)))
            {
                const char *name = ent->d_name;
                // 跳过"."和".."
                if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
                    continue;

                evbuffer_add_printf(evb,
                                    "    <li><a href=\"%s\">%s</a>\n",
                                    name, name); // 注意：实际应用中应对HTML特殊字符进行转义
            }
            evbuffer_add_printf(evb, "  </ul>\n</body>\n</html>\n");
            closedir(d);

            // 设置HTML内容类型
            evhttp_add_header(evhttp_request_get_output_headers(req),
                              "Content-Type", "text/html");
        }
        // 处理文件请求
        else
        {
            const char *type = guess_content_type(decoded_path);

            // 打开文件
            if ((fd = open(whole_path, O_RDONLY)) < 0)
            {
                perror("open");
                goto err;
            }

            // 获取文件状态
            if (fstat(fd, &st) < 0)
            {
                perror("fstat");
                goto err;
            }

            // 设置内容类型
            evhttp_add_header(evhttp_request_get_output_headers(req),
                              "Content-Type", type);

            // 使用零拷贝发送文件
            evbuffer_add_file(evb, fd, 0, st.st_size);
        }

        // 发送成功响应
        evhttp_send_reply(req, 200, "OK", evb);
        goto done;

    err:
        // 发送404错误
        evhttp_send_error(req, 404, "Document was not found");
        if (fd >= 0)
            close(fd);

    done:
        // 清理资源
        if (decoded)
            evhttp_uri_free(decoded);
        if (decoded_path)
            free(decoded_path);
        if (whole_path)
            free(whole_path);
        if (evb)
            evbuffer_free(evb);
    }

 

    /**
     * @brief 信号处理函数  捕获Ctrl+C
     * @param sig 信号值
     * @param events 事件类型
     * @param arg 用户数据（event_base对象）
     */
    static void do_term(int sig, short events, void *arg)
    {
        event_base *base = (event_base *)arg;
        event_base_loopbreak(base);
        fprintf(stderr, "Received signal %d, terminating\n", sig);
    }

    /**
     * @brief 显示监听套接字信息
     * @param handle 绑定的套接字句柄
     * @return 成功返回0，失败返回1
     */
    static int display_listen_sock(struct evhttp_bound_socket *handle)
    {
        struct sockaddr_storage ss;
        evutil_socket_t fd;
        ev_socklen_t socklen = sizeof(ss);
        char addrbuf[128];
        void *inaddr;
        const char *addr;
        int got_port = -1;

        // 获取套接字描述符
        fd = evhttp_bound_socket_get_fd(handle);
        memset(&ss, 0, sizeof(ss));
        if (getsockname(fd, (struct sockaddr *)&ss, &socklen))
        {
            perror("getsockname() failed");
            return 1;
        }

        // 处理IPv4地址
        if (ss.ss_family == AF_INET)
        {
            got_port = ntohs(((struct sockaddr_in *)&ss)->sin_port);
            inaddr = &((struct sockaddr_in *)&ss)->sin_addr;
        }
        // 处理IPv6地址
        else if (ss.ss_family == AF_INET6)
        {
            got_port = ntohs(((struct sockaddr_in6 *)&ss)->sin6_port);
            inaddr = &((struct sockaddr_in6 *)&ss)->sin6_addr;
        }
        // 处理Unix域套接字
        else if (ss.ss_family == AF_UNIX)
        {
            printf("Listening on Unix socket: %s\n", ((struct sockaddr_un *)&ss)->sun_path);
            return 0;
        }

        // 未知地址族
        else
        {
            fprintf(stderr, "Unsupported address family %d\n", ss.ss_family);
            return 1;
        }

        // 转换地址为可读格式
        addr = evutil_inet_ntop(ss.ss_family, inaddr, addrbuf, sizeof(addrbuf));
        if (addr)
        {
            printf("Listening on %s:%d\n", addr, got_port);
            evutil_snprintf(uri_root, sizeof(uri_root), "http://%s:%d", addr, got_port);
        }
        else
        {
            fprintf(stderr, "evutil_inet_ntop failed\n");
            return 1;
        }

        return 0;
    }

    /**
     * @brief 主函数
     * @param argc 命令行参数个数
     * @param argv 命令行参数数组
     * @return 程序退出状态
     */
    int test()
    {

        evhttp *http = NULL;
        evhttp_bound_socket *handle = NULL;
        evconnlistener *lev = NULL;
        event *term = NULL;

        int ret = 0;
        options opt = {
            8000,
            true,
            true,
            nullptr, //"./server.sock",
            "./web",
        };

        // 设置标准输出无缓冲
        // setbuf(stdout, NULL);
        // setbuf(stderr, NULL);

        // 启用调试日志（如果设置了详细模式）
        if (opt.verbose)
        {
            event_enable_debug_logging(EVENT_DBG_ALL);
        }

        // 创建事件配置
        event_config *cfg = event_config_new();
        event_base *base = event_base_new_with_config(cfg);
        if (!base)
        {
            fprintf(stderr, "Couldn't create event_base\n");
            ret = 1;
            goto err;
        }
        event_config_free(cfg);
        cfg = NULL;

        // 创建HTTP服务器实例
        http = evhttp_new(base);
        if (!http)
        {
            fprintf(stderr, "couldn't create evhttp\n");
            ret = 1;
            goto err;
        }

        // 注册特定路径回调
        evhttp_set_cb(http, "/dump", dump_request_cb, NULL);

        // 设置通用请求回调
        evhttp_set_gencb(http, send_document_cb, &opt);

        // 绑定Unix域套接字或TCP套接字
        if (opt.unixsock)
        {

            struct sockaddr_un addr;

            // 删除已存在的套接字文件
            if (opt.unlink && (unlink(opt.unixsock) == -1) && errno != ENOENT)
            {
                perror("unlink");
                ret = 1;
                goto err;
            }

            // 配置Unix域套接字地址
            memset(&addr, 0, sizeof(addr));
            addr.sun_family = AF_UNIX;
            strncpy(addr.sun_path, opt.unixsock, sizeof(addr.sun_path) - 1);

            // 创建并绑定监听器
            lev = evconnlistener_new_bind(base, NULL, NULL,
                                          LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1,
                                          (struct sockaddr *)&addr, sizeof(addr));
            if (!lev)
            {
                perror("evconnlistener_new_bind");
                ret = 1;
                goto err;
            }

            // 将监听器绑定到HTTP服务器
            handle = evhttp_bind_listener(http, lev);
            if (!handle)
            {
                fprintf(stderr, "couldn't bind listener\n");
                ret = 1;
                goto err;
            }

            printf("Listening on Unix socket: %s\n", opt.unixsock);
        }
        // 绑定TCP端口
        else
        {
            handle = evhttp_bind_socket_with_handle(http, "0.0.0.0", opt.port);
            if (!handle)
            {
                fprintf(stderr, "couldn't bind to port %d\n", opt.port);
                ret = 1;
                goto err;
            }

            // 显示监听信息
            if (display_listen_sock(handle))
            {
                ret = 1;
                goto err;
            }
        }

        // 注册信号处理
        term = evsignal_new(base, SIGINT, do_term, base);
        if (!term || event_add(term, NULL) == -1)
        {
            fprintf(stderr, "Could not create/add signal event\n");
            goto err;
        }

        // 启动事件循环
        printf("Server running on document root: %s\n", opt.docroot);
        event_base_dispatch(base);
        printf("Server stopped\n");

    err:
        // 清理资源
        if (term)
            event_free(term);
        if (lev)
            evconnlistener_free(lev);
        if (http)
            evhttp_free(http);
        if (base)
            event_base_free(base);
        if (cfg)
            event_config_free(cfg);

        return ret;
    }
}

int main()
{
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
    {
        std::cerr << "Failed to ignore SIGPIPE" << std::endl;
        return -1;
    }
    // tcpClient::test("read");
    // tcpServer::test();
    httpServer::test();
    return 0;
}