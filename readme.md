 cd libevent-2.1.12-stable/


cmake ..  或者 cmake .. -DCMAKE_INSTALL_PREFIX=你的安装目录
make -j8
make install

如果找不到库
sudo find / -name libevent-2.1.so.7 2>/dev/null

sudo sh -c 'echo "/usr/local/lib" >> /etc/ld.so.conf'

sudo ldconfig
