#include <iostream>
#include <signal.h>

#include <sys/uio.h> // 用于iovec
#include <algorithm> // 用于std::min
#include <fstream>   // 用于文件操作
#include <vector>
#include <cstring>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <atomic>
#include <sys/inotify.h>

#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>

void print_features(event_base *base)
{
    // event_base_get_features  获取当前 event_base 实例所支持的事件处理特性 注意这个只是支持 并不一定启用了
    int features = event_base_get_features(base);
    std::cout << "support features:" << std::endl;
    std::cout << "  EV_FEATURE_ET: " << ((features & EV_FEATURE_ET) ? "YES" : "NO") << std::endl;
    std::cout << "  EV_FEATURE_O1: " << ((features & EV_FEATURE_O1) ? "YES" : "NO") << std::endl;
    std::cout << "  EV_FEATURE_FDS: " << ((features & EV_FEATURE_FDS) ? "YES" : "NO") << std::endl;

    std::cout << "enable I/O: " << event_base_get_method(base) << std::endl;
}

event_base *config_new(int useCfg = false, int fds = false)
{
    event_base *base = nullptr;

    if (!useCfg)
    {
        base = event_base_new();
        if (!base)
        {
            std::cerr << "base new fail" << std::endl;
            return nullptr;
        }
        std::cout << "使用默认配置创建 event_base" << std::endl;
        print_features(base);
        return base;
    }

    std::cout << "自定义配置创建 event_base" << std::endl;

    // 创建配置对象
    event_config *cfg = event_config_new();
    if (!cfg)
    {
        std::cerr << "event_config_new failed!" << std::endl;
        return nullptr;
    }

    // 调试： 显示系统支持的后端I/O方法
    const char **methods = event_get_supported_methods();
    std::cout << "Supported I/O methods:" << std::endl;
    for (int i = 0; methods[i] != NULL; i++)
    {
        std::cout << "  " << methods[i] << std::endl;
    }

    // 设置特性  支持任意文件描述符（非仅socket）
    // 设置了EV_FEATURE_FDS 其他特征就无法设置，例如旧内核的 epoll 不支持非socket fd 的 ET 模式
    if (fds && event_config_require_features(cfg, EV_FEATURE_FDS) != 0)
    {
        std::cerr << "EV_FEATURE_FDS not supported " << std::endl;
        event_config_free(cfg);
        return nullptr;
    }

    // event_config_require_features(cfg,  EV_FEATURE_ET); // 设置ET

    /// 设置避免使用的网络模型  epoll > kqueue > poll > select
    // event_config_avoid_method(cfg, "poll");
    // event_config_avoid_method(cfg, "epoll");

    // 应用配置创建事件基础 Linux默认是 epoll LT模式 前提未启用 EV_FEATURE_FDS
    base = event_base_new_with_config(cfg);
    event_config_free(cfg);

    if (!base)
    {

        // 自定义配置失败时回退到默认配置
        std::cerr << "event_base_new_with_config fail" << std::endl;
        base = event_base_new();
        if (!base)
        {
            std::cerr << "base new fail" << std::endl;
            return nullptr;
        }
    }
    print_features(base);
    return base;
}

namespace signal_event
{

    void ctrl_c(evutil_socket_t, short, void *arg)
    {
        static int cnum = 0;
        std::cout << "\nSIGINT(Ctrl+C) received. Exiting..." << std::endl;
        event_base *base = static_cast<event_base *>(arg);
        if (++cnum >= 3)
        {
            timeval timeout = {3, 0};
            event_base_loopexit(base, &timeout);
        }
    }

    void on_kill(evutil_socket_t, short, void *arg)
    {

        static int cnum = 0;
        std::cout << "\nSIGTERM(kill) received. Exiting..." << std::endl;
        event *ev = static_cast<event *>(arg);
        if (!event_pending(ev, EV_SIGNAL, nullptr))
        {
            event_add(ev, nullptr);
        }
        if (++cnum >= 3)
        {
            event_base *base = event_get_base(ev);
            timeval timeout = {3, 0};
            event_base_loopexit(base, &timeout);
        }
    }

    int test_signal()
    {
        event_base *base = config_new();
        if (!base)
        {
            return -1;
        }
        // 2. 创建SIGINT事件 (Ctrl+C)
        event *sigint_event = event_new(base, SIGINT, EV_SIGNAL | EV_PERSIST, ctrl_c, base);
        // 传递base作为回调参数
        if (!sigint_event || event_add(sigint_event, nullptr) < 0)
        {
            std::cerr << "Failed to create/add SIGINT event" << std::endl;
            return 1;
        }

        // 3. 创建SIGTERM事件 (kill命令)
        event *sigterm_event = event_new(base, SIGTERM, EV_SIGNAL, on_kill, event_self_cbarg());

        if (!sigterm_event || event_add(sigterm_event, nullptr) < 0)
        {
            std::cerr << "Failed to create/add SIGTERM event" << std::endl;
            event_free(sigint_event);
            return 1;
        }

        std::cout << "Signal handler running. Press Ctrl+C or use 'kill' to terminate." << std::endl;

        event_base_dispatch(base);

        event_free(sigint_event);
        event_free(sigterm_event);

        return 0;
    }

}
namespace timer_event
{

    void timer1(evutil_socket_t, short, void *)
    {
        std::cout << "timer1" << std::endl;
    }

    void timer2(evutil_socket_t, short, void *)
    {
        std::cout << "timer2" << std::endl;
    }

    void timer3(evutil_socket_t, short, void *)
    {
        std::cout << "timer3" << std::endl;
    }

    int test_timer()
    {
        event_base *base = config_new();
        if (!base)
        {
            return -1;
        }
        // 非持久处理器
        event *ev1 = evtimer_new(base, timer1, nullptr);
        timeval t1 = {1, 0};
        evtimer_add(ev1, &t1);

        // 持久定时器 默认使用二叉堆(O(log n))
        event *ev2 = event_new(base, -1, EV_PERSIST, timer2, nullptr);
        timeval t2 = {3, 0};
        evtimer_add(ev2, &t2);

        // 改变定时器结构
        // event_base_init_common_timeout是Libevent提供的一个性能优化函数，主要解决大量相同超时时间定时器
        event *ev3 = event_new(base, -1, EV_PERSIST, timer3, nullptr);
        timeval tv_in = {6, 0};
        const timeval *t3 = event_base_init_common_timeout(base, &tv_in);
        // 优化后使用队列/时间轮(O(1))
        evtimer_add(ev3, t3);

        event_base_dispatch(base);

        event_free(ev1);
        event_free(ev2);
        event_free(ev3);

        return 0;
    }
}

namespace file_event
{
    struct FileState
    {
        evutil_socket_t fd;
        off_t last_pos;
        event *file_event; // 关联的文件事件
        int inotify_fd;    // inotify描述符
    };

    void signal_handler(evutil_socket_t, short, void *arg)
    {
        event_base *base = static_cast<event_base *>(arg);
        std::cout << "\nShutting down..." << std::endl;
        event_base_loopbreak(base);
    }

    // 文件修改回调（当文件被写入时触发）
    void inotify_callback(evutil_socket_t inotify_fd, short, void *arg)
    {
        FileState *state = static_cast<FileState *>(arg);

        char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
        const struct inotify_event *event;

        // 读取inotify事件
        ssize_t len = read(inotify_fd, buf, sizeof(buf));
        if (len <= 0)
            return;

        // 处理所有事件
        for (char *ptr = buf; ptr < buf + len; ptr += sizeof(struct inotify_event) + event->len)
        {
            event = reinterpret_cast<const struct inotify_event *>(ptr);

            if (event->mask & IN_MODIFY)
            {
                // 文件被修改，重新激活文件读取事件
                event_add(state->file_event, nullptr);
                std::cout << "File modified, reactivating read handler\n";
            }
        }
    }

    void read_file(evutil_socket_t fd, short, void *arg)
    {
        FileState *state = static_cast<FileState *>(arg);
        struct stat file_stat;

        if (fstat(fd, &file_stat) < 0)
        {
            perror("fstat failed");
            return;
        }

        // 检查是否有新数据
        if (file_stat.st_size > state->last_pos)
        {
            lseek(fd, state->last_pos, SEEK_SET);
            char buf[1024];

            while (true)
            {
                ssize_t nread = read(fd, buf, sizeof(buf) - 1);
                if (nread <= 0)
                    break;

                buf[nread] = '\0';
                std::cout << buf;
                state->last_pos += nread;
            }
        }

        // 到达当前文件末尾（但保持监听）
        if (state->last_pos == file_stat.st_size)
        {
            // 仅注销事件但不释放资源
            event_del(state->file_event);
            std::cout << "Reached EOF, waiting for new writes...\n";
        }
    }

    int test_file()
    {
        event_base *base = config_new(true, true);
        if (!base)
        {
            return -1;
        }
        const char *filename = "./log";

        // 1. 打开日志文件
        int fd = open(filename, O_RDWR | O_CREAT | O_NONBLOCK, 0644);
        if (fd < 0)
        {
            perror("open failed");
            return -1;
        }

        // 2. 定位到文件末尾
        off_t initial_pos = lseek(fd, 0, SEEK_END);

        // 3. 初始化状态结构体
        FileState *state = new FileState();
        state->fd = fd;
        state->last_pos = initial_pos;

        // 4. 创建文件读取事件（非持久）
        state->file_event = event_new(base, fd, EV_READ, read_file, state);
        event_add(state->file_event, nullptr);

        // 5. 设置inotify监控文件修改
        state->inotify_fd = inotify_init1(IN_NONBLOCK);
        if (state->inotify_fd < 0)
        {
            perror("inotify_init failed");
            close(fd);
            delete state;
            return -2;
        }

        // 添加对文件修改的监控
        int wd = inotify_add_watch(state->inotify_fd, filename, IN_MODIFY);
        if (wd < 0)
        {
            perror("inotify_add_watch failed");
            close(state->inotify_fd);
            close(fd);
            delete state;
            return -3;
        }

        // 6. 创建inotify事件
        event *inotify_event = event_new(
            base,
            state->inotify_fd,
            EV_READ | EV_PERSIST,
            inotify_callback,
            state);
        event_add(inotify_event, nullptr);

        // 7. 设置信号处理
        event *sigint = evsignal_new(base, SIGINT, signal_handler, base);
        event *sigterm = evsignal_new(base, SIGTERM, signal_handler, base);
        event_add(sigint, nullptr);
        event_add(sigterm, nullptr);

        std::cout << "Monitoring " << filename << " for continuous writes\n"
                  << "Press Ctrl+C to exit" << std::endl;

        // 8. 启动事件循环
        event_base_dispatch(base);

        // 9. 清理资源
        inotify_rm_watch(state->inotify_fd, wd);
        close(state->inotify_fd);
        event_free(inotify_event);
        event_free(sigterm);
        event_free(sigint);
        event_free(state->file_event);
        close(fd);
        delete state;

        std::cout << "Clean exit" << std::endl;
        return 0;
    }
}

namespace filter_event
{

    // 定义阈值常量
    const size_t LARGE_DATA_THRESHOLD = 1024;

    bufferevent_filter_result filter_in(evbuffer *s, evbuffer *d, ev_ssize_t,
                                        bufferevent_flush_mode, void *)
    {
        size_t len = evbuffer_get_length(s);
        if (len == 0)
            return BEV_OK;

        std::vector<char> buf(len + 12);          // 预留前缀空间
        evbuffer_remove(s, buf.data() + 11, len); // 偏移11字节用于前缀

        memcpy(buf.data(), "[filter_in]", 11);
        buf[len + 11] = '\0';

        evbuffer_add(d, buf.data(), len + 11);
        return BEV_OK;
    }

    bufferevent_filter_result filter_out(evbuffer *s, evbuffer *d, ev_ssize_t,
                                         bufferevent_flush_mode, void *)
    {
        size_t len = evbuffer_get_length(s);
        if (len == 0)
            return BEV_OK;

        std::vector<char> buf(len + 12);
        evbuffer_remove(s, buf.data() + 12, len);

        memcpy(buf.data(), "[filter_out]", 12);
        buf[len + 12] = '\0';

        evbuffer_add(d, buf.data(), len + 12);
        return BEV_OK;
    }

    void write_large_data_to_file(const char *data, size_t len)
    {
        static int file_counter = 0;
        std::string filename = "large_data_" + std::to_string(file_counter++) + ".dat";

        std::ofstream outfile(filename, std::ios::binary);
        if (!outfile)
        {
            std::cerr << "Failed to open file: " << filename << std::endl;
            return;
        }

        outfile.write(data, len);
        outfile.close();

        std::cout << "Large data (" << len << " bytes) written to file: " << filename << std::endl;
    }

    void read_cb(bufferevent *bev, void *)
    {
        evbuffer *input = bufferevent_get_input(bev);
        size_t len = evbuffer_get_length(input);
        if (len == 0)
            return;

        if (len > LARGE_DATA_THRESHOLD)
        {
            // 大数据量处理 - 写入文件
            evbuffer_iovec v[2];
            int n_vec = evbuffer_peek(input, len, NULL, v, 2);

            for (int i = 0; i < n_vec; ++i)
            {
                write_large_data_to_file(static_cast<const char *>(v[i].iov_base), v[i].iov_len);
            }

            evbuffer_drain(input, len);

            const char *reply = "[Processed large data and saved to file]";
            bufferevent_write(bev, reply, strlen(reply));
        }
        else
        {
            // 小数据量处理 - 直接打印
            size_t read_len = std::min(len, static_cast<size_t>(1024));
            std::vector<char> buf(read_len + 1);

            int actual_len = bufferevent_read(bev, buf.data(), read_len);
            if (actual_len > 0)
            {
                buf[actual_len] = '\0';
                std::cout << "Small data received (" << actual_len << " bytes): " << buf.data() << std::endl;

                // 回显数据
                bufferevent_write(bev, buf.data(), actual_len);
            }
        }
    }

    void write_cb(bufferevent *bev, void *)
    {
        evbuffer *output = bufferevent_get_output(bev);
        size_t pending = evbuffer_get_length(output);
        std::cout << "write_cb, pending bytes: " << pending << std::endl;
    }

    void event_cb(bufferevent *bev, short events, void *)
    {
        if (events & BEV_EVENT_ERROR)
        {
            std::cerr << "Error from bufferevent: "
                      << evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()) << std::endl;
        }
        if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR))
        {
            std::cout << "Connection closed" << std::endl;
            bufferevent_free(bev);
        }
    }

    void listen_cb(struct evconnlistener *, evutil_socket_t s, struct sockaddr *,
                   int, void *arg)
    {
        event_base *base = (event_base *)arg;
        evutil_make_socket_nonblocking(s);

        bufferevent *bev = bufferevent_socket_new(base, s, BEV_OPT_CLOSE_ON_FREE);
        if (!bev)
        {
            std::cerr << "Error creating bufferevent" << std::endl;
            return;
        }

        bufferevent_setwatermark(bev, EV_READ, 0, LARGE_DATA_THRESHOLD);

        bufferevent *bev_filter = bufferevent_filter_new(
            bev, filter_in, filter_out, BEV_OPT_CLOSE_ON_FREE, nullptr, nullptr);

        bufferevent_setcb(bev_filter, read_cb, write_cb, event_cb, nullptr);
        bufferevent_enable(bev_filter, EV_READ | EV_WRITE);
    }

    int test_filter()
    {
        event_base *base = config_new();
        if (!base)
        {
            return -1;
        }
        sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_port = htons(8000);

        evconnlistener *ev = evconnlistener_new_bind(
            base, listen_cb, base,
            LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE | LEV_OPT_CLOSE_ON_EXEC,
            10, (sockaddr *)&sin, sizeof(sin));

        if (!ev)
        {
            std::cerr << "Couldn't create listener" << std::endl;
            return 1;
        }

        event_base_dispatch(base);
        evconnlistener_free(ev);
        return 0;
    }

}

int main()
{
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
    {
        std::cerr << "Failed to ignore SIGPIPE" << std::endl;
        return -1;
    }
    file_event::test_file();
    return 0;
}