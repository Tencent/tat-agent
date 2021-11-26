echo "|-正在尝试从ntpdate ntp.ntsc.ac.cn同步时间..";
ntpdate -u ntp.ntsc.ac.cn
if [ $? = 1 ];then
    echo "|-正在尝试从0.asia.pool.ntp.org同步时间..";
    ntpdate -u 0.asia.pool.ntp.org
fi
echo "|-正在尝试将当前系统时间写入硬件..";
hwclock -w
date
echo "|-时间同步完成!";
