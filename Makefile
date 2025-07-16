# 编译器配置
CXX := g++
CXXFLAGS := -Wall  -g   # 编译选项：全警告+优化
SRCS := $(wildcard *.cpp)       # 获取所有 .cpp 文件
TARGETS := $(SRCS:.cpp=)        # 生成同名可执行文件列表
LDLIBS := -levent -levent_pthreads -lpthread

# 默认目标：编译所有可执行文件
all: $(TARGETS)

# 模式规则：每个可执行文件依赖同名.cpp
# $@ = 目标名(如 hello), $< = 依赖文件(如 hello.cpp)
%: %.cpp
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDLIBS)

# 清理所有生成的可执行文件
clean:
	rm -f $(TARGETS)

# 声明伪目标（防止与同名文件冲突）
.PHONY: all clean