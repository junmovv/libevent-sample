#include <iostream>
#include <cstring>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <signal.h>
#define use_socket
#define use_event_buff

namespace tcpClient
{

    /**
     * 客户端事件回调函数
     * @param be bufferevent指针
     * @param events 触发的事件标志
     * @param arg 用户自定义参数(此处未使用)
     *
     * 处理事件包括：
     * 1. 连接成功
     * 2. 读取超时
     * 3. 错误发生
     * 4. 连接断开(EOF)
     */
    void client_event_cb(bufferevent *be, short events, void *)
    {
        std::cout << "client_event_cb: events=" << events << std::endl;

        if (events & BEV_EVENT_CONNECTED)
        {
            std::cout << "BEV_EVENT_CONNECTED: Connection established successfully" << std::endl;
            // 触发write回调，开始发送数据
            bufferevent_trigger(be, EV_WRITE, 0);
            return; // 连接成功不需要释放资源
        }

        // 读取超时事件
        if (events & BEV_EVENT_TIMEOUT && events & BEV_EVENT_READING)
        {
            std::cout << "BEV_EVENT_READING|BEV_EVENT_TIMEOUT: Read operation timed out" << std::endl;
        }
        // 错误事件
        else if (events & BEV_EVENT_ERROR)
        {
            std::cout << "BEV_EVENT_ERROR: "
                      << evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR())
                      << std::endl;
        }
        // 连接关闭事件
        else if (events & BEV_EVENT_EOF)
        {
            std::cout << "BEV_EVENT_EOF: Connection closed by server" << std::endl;
        }

        // 释放资源（确保只释放一次）
        if (be)
        {
            // 先禁用事件避免重复触发
            bufferevent_disable(be, EV_READ | EV_WRITE);
            // 当调用bufferevent_free(bev)时，相关的socket和事件都会被释放
            // 如果这是最后一个活跃的事件源，事件循环自然就会退出
            bufferevent_free(be);
        }
    }

    /**
     * 客户端写回调函数
     * @param be bufferevent指针
     * @param arg 用户自定义参数(文件指针)
     *
     * 处理数据发送逻辑，当可以写入数据时被触发
     */
    void client_write_cb(bufferevent *be, void *arg)
    {
        std::cout << "client_write_cb" << std::endl;
        FILE *fp = (FILE *)arg;
        if (!fp)
        {
            bufferevent_disable(be, EV_WRITE);
            return;
        }

        char data[1024] = {0};
        int len = fread(data, 1, sizeof(data) - 1, fp);

        if (len <= 0)
        {
            // 禁用写事件而不是立即释放，确保缓冲区数据发送完成
            bufferevent_disable(be, EV_WRITE);
            return;
        }

        // 写入发送缓冲区
        bufferevent_write(be, data, len);
    }

    /**
     * 客户端读回调函数
     * @param be bufferevent指针
     * @param arg 用户自定义参数(未使用)
     *
     * 处理从服务器接收的数据
     */
    void client_read_cb(bufferevent *, void *)
    {
        std::cout << "[client_R]" << std::flush;
        // 可以添加实际的数据处理逻辑，例如：
        // char buf[1024];
        // int n = bufferevent_read(be, buf, sizeof(buf));
        // if (n > 0) {
        //     process_received_data(buf, n);
        // }
    }

    /**
     * 测试客户端函数
     * @param base event_base指针
     * @return 执行状态(0表示成功)
     *
     * 初始化客户端连接并启动事件循环
     */
    int test_client()
    {
        event_base *base = event_base_new();
        if (!base)
        {
            return -1;
        }
        // 创建新的bufferevent
        bufferevent *bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
        if (!bev)
        {
            std::cerr << "Error creating bufferevent" << std::endl;
            return -1;
        }

        // 设置服务器地址
        sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_port = htons(9999);
        evutil_inet_pton(AF_INET, "10.184.148.247", &sin.sin_addr.s_addr);

        // 打开要发送的文件
        FILE *fp = fopen("server.hpp", "rb");
        if (!fp)
        {
            std::cerr << "Error opening file" << std::endl;
            bufferevent_free(bev);
            return -1;
        }

        // 设置回调函数
        bufferevent_setcb(bev, client_read_cb, client_write_cb, client_event_cb, fp);

        // 启用读写事件
        bufferevent_enable(bev, EV_READ | EV_WRITE);

        // 设置超时（建议添加）
        timeval tv_read = {10, 0};  // 10秒读超时
        timeval tv_write = {10, 0}; // 10秒写超时
        bufferevent_set_timeouts(bev, &tv_read, &tv_write);

        // 发起连接
        int re = bufferevent_socket_connect(bev, (sockaddr *)&sin, sizeof(sin));
        if (re != 0)
        {
            std::cerr << "Connect failed: "
                      << evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR())
                      << std::endl;
            bufferevent_free(bev);
            fclose(fp);
            return -1;
        }

        std::cout << "Connection initiated" << std::endl;

        // 进入事件主循环
        event_base_dispatch(base);
        fclose(fp);
        std::cout << "exit" << std::endl;
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

    int test_server()
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
    tcpServer::test_server();
    return 0;
}