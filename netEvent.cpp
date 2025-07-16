#include <iostream>
#include <cstring>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <signal.h>
#define use_socket
#define use_event_buff
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

int main()
{
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
    {
        std::cerr << "Failed to ignore SIGPIPE" << std::endl;
        return -1;
    }
    tcpClient::test("read");
    // tcpServer::test();
    return 0;
}