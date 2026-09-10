#include <windows.h>
static void out(const char *s){DWORD n;unsigned len=0;while(s[len])len++;WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),s,len,&n,0);}
static void hex(unsigned long long v){char s[19]="0x0000000000000000";for(unsigned i=0;i<16;i++)s[17-i]="0123456789abcdef"[(v>>(i*4))&15];out(s);}
static void measure(HDC dc){SIZE z={-99,-99};TEXTMETRICW tm={0};BOOL r=GetTextExtentPointW(dc,L"A",1,&z);out(" extent=");hex(r);out(" width=");hex(z.cx);out(" height=");hex(z.cy);r=GetTextMetricsW(dc,&tm);out(" metrics=");hex(r);out(" tmHeight=");hex(tm.tmHeight);out("\r\n");}
void mainCRTStartup(void){out("B3630-DC-PROBE desktop=");hex((ULONG_PTR)GetDesktopWindow());out("\r\n");for(unsigned i=0;i<3;i++){HDC dc=GetDC(0);out("screen-dc=");hex((ULONG_PTR)dc);measure(dc);HGDIOBJ f=SelectObject(dc,GetStockObject(DEFAULT_GUI_FONT));out("selected-previous=");hex((ULONG_PTR)f);measure(dc);SelectObject(dc,f);out("release=");hex(ReleaseDC(0,dc));out("\r\n");}ExitProcess(0);}
