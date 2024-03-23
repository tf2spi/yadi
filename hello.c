#include <stdio.h>

int __declspec(dllexport) hello()
{
	return 0;
}

int main()
{
	printf("Hello World!\n");
	return 0;
}
