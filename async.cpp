//#include <coroutine>
#include <experimental/coroutine>
#include <future>
#include <numeric>
#include <stdio.h>

#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#define ZBREAK() __builtin_trap()
#define ZASSERT(expr)                                                                                                                                                                                  \
	do                                                                                                                                                                                                 \
	{                                                                                                                                                                                                  \
		if(!(expr))                                                                                                                                                                                    \
		{                                                                                                                                                                                              \
			ZBREAK();                                                                                                                                                                                  \
		}                                                                                                                                                                                              \
	} while(0)

int64_t Ticks()
{
	timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	return 1000000000ll * ts.tv_sec + ts.tv_nsec;
}

int64_t TicksPerSecond()
{
	return 1000000000ll;
}

double Seconds()
{
	static int64_t TickStart = Ticks();
	static int64_t TPS = TicksPerSecond();
	int64_t TicksNow = Ticks();

	return double(TicksNow - TickStart) / TPS;
}

FILE* F;
void init_openssl()
{
}

void ReadIt(BIO* Bio)
{
	int FailCount = 0;
	double Time = Seconds();
	while(true)
	{
		char buffer[256 + 1];
		int x = BIO_read(Bio, buffer, 256);
		if(x == 0)
		{
			printf("connection closed!\n");
			return;
		}
		else if(x < 0)
		{
			if(!BIO_should_retry(Bio))
			{
				printf("Not Retry fail!!\n");
				ZBREAK();
			}
			if(Seconds() - Time > 5.f)
			{
				return;
			}
		}
		else
		{
			Time = Seconds();
			FailCount = 0;
			buffer[x] = '\0';
			int c = fwrite(buffer, x, 1, F);
			ZASSERT(c == 1);
			printf("rec : '%s'", buffer);
		}
	}
}

void WriteIt(BIO* Bio, const char* bytes)
{
	int len = strlen(bytes);
	while(len > 0)
	{
		int w = BIO_write(Bio, bytes, len);
		if(w > 0)
		{
			ZASSERT(w <= len);
			len -= w;
			bytes += w;
		}
		else
		{
			if(!BIO_should_retry(Bio))
			{
				printf("!RETRY\n");
				ZBREAK();
			}
		}
	}
}

void Download()
{

	// const char* req = "GET /index.htm HTTP/1.1\n"
	// 				  "User-Agent: Mozilla/4.0 (compatible; MSIE5.01; Windows NT)\n"
	// 				  "Host: www.tutorialspoint.com\n"
	// 				  "Accept-Language: en-us\n\n";
	const char* req = "GET / HTTP/1.1\n"
					  "User-Agent: Mozilla/4.0 (compatible; MSIE5.01; Windows NT)\n"
					  "Host: tile.openstreetmap.de\n"
					  "Accept-Language: en-us\n\n";

	// https://tile.openstreetmap.de/7/64/43.png
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();
	BIO* Bio = BIO_new_connect("tile.openstreetmap.de:80");
	// BIO* Bio = BIO_new_connect("www.tutorialspoint.com:80");
	BIO_set_nbio(Bio, 1);
	while(1)
	{
		int r = BIO_do_connect(Bio);
		if(r <= 0)
		{
			ERR_print_errors_fp(stderr);
			printf("connection failed %d \n", r);

			if(BIO_should_retry(Bio))
			{
				printf("should retry!!\n");
			}
			else
			{
				ZBREAK();
			}
		}
		else
		{
			break;
		}
	}
	printf("I AM Connected\n");
	WriteIt(Bio, req);
	F = fopen("fisk.bin", "w");
	ReadIt(Bio);
	fclose(F);
	BIO_free_all(Bio);
	printf("done, closing\n");
	Bio = 0;

	// if(0)
	// {
	// 	SSL_load_error_strings();
	// 	OpenSSL_add_ssl_algorithms();

	// 	SSL_CTX* ctx = 0;
	// 	{
	// 		const SSL_METHOD* method = 0;
	// 		method = SSLv23_server_method();
	// 		ctx = SSL_CTX_new(method);
	// 		if(!ctx)
	// 		{
	// 			perror("Unable to create SSL context");
	// 			ERR_print_errors_fp(stderr);
	// 			ZBREAK();
	// 		}
	// 	}
	// 	{

	// 		SSL_CTX_set_ecdh_auto(ctx, 1);

	// 		/* Set the key and cert */
	// 		if(SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0)
	// 		{
	// 			ERR_print_errors_fp(stderr);
	// 			ZBREAK();
	// 		}

	// 		if(SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0)
	// 		{
	// 			ERR_print_errors_fp(stderr);
	// 			ZBREAK();
	// 		}
	// 	}
	// }
	printf("didnt crash\n");
}

using namespace std;
using namespace std::experimental;
// struct Fisk
// {
// 	int r;

// 	Fisk()
// 	{
// 		printf("fisk created\n");
// 	}
// 	~Fisk()
// 	{
// 		printf("fisk destroyed\n");
// 	}

// 	struct promise_type
// 	{

// 		int stored;
// 		promise_type()
// 		{
// 			printf("promise_type created\n");
// 		}
// 		~promise_type()
// 		{
// 			printf("promise_type destroyed\n");
// 		}
// 		Fisk initial_suspend()
// 		{
// 			printf("initial_suspend\n");
// 			return Fisk();
// 		}
// 		void yield_value(int r)
// 		{
// 			stored = r;
// 		}

// 	};
// };

// Fisk foo()
// {
// 	int i = 0;
// 	while(i < 100)
// 		co_yield i;
// }

struct resumable_thing
{
	struct promise_type;
	coroutine_handle<promise_type> coroutine = nullptr;

	explicit resumable_thing(coroutine_handle<promise_type> co)
		: coroutine(co)
	{
		printf("resumable_thing::resumable_thing handle %p\n", &coroutine);
	}
	resumable_thing() = default;
	resumable_thing(const resumable_thing&) = delete;
	resumable_thing& operator=(const resumable_thing&) = delete;
	resumable_thing(resumable_thing&& other)
		: coroutine(other.coroutine)
	{
		other.coroutine = 0;
	}
	resumable_thing& operator=(resumable_thing&& other)
	{
		if(&other != this)
		{
			coroutine = other.coroutine;
			other.coroutine = 0;
		}
		return *this;
	}

	~resumable_thing()
	{
		printf("resumable_thing::~resumable_thing\n");
		if(coroutine)
		{
			coroutine.destroy();
		}
	}
	void resume()
	{
		coroutine.resume();
	}
	struct promise_type
	{
		promise_type()
		{
			printf("promise_type::promise_type\n");
		}

		~promise_type()
		{
			printf("promise_type::~promise_type\n");
		}
		int value;
		resumable_thing get_return_object()
		{
			return resumable_thing(coroutine_handle<promise_type>::from_promise(*this));
		}
		auto initial_suspend()
		{
			return suspend_never{};
		}
		auto final_suspend()
		{
			printf("final_suspend\n");
			return suspend_always{};
		}
		void return_value(int a)
		{
			printf("return value %d\n", a);
			value = a;
		}
		void unhandled_exception()
		{
		}
	};
	int get()
	{
		return coroutine.promise().value;
	}
};
struct suspend_sometimes
{
	bool await_ready()
	{
		return false;
	}
	template <typename T>
	bool await_suspend(const coroutine_handle<T>& h)
	{
		int r = rand() % 10;
		printf("susp %d :: %p\n", r, &h);
		return r < 2;
	}
	bool await_resume()
	{
		return false;
	}
};

resumable_thing my_coroutine() noexcept
{
	printf("a\n");
	co_await suspend_never{};
	printf("b\n");
	for(int i = 0; i < 100; ++i)
	{
		co_await suspend_sometimes{};
		printf("c\n");
	}
	co_await suspend_always{};
	printf("d\n");
	co_return 42;
}
#include <stdio.h>
#include <sys/socket.h>

int main() noexcept
{
	Download();
	return 0;
	resumable_thing t = my_coroutine();
	t.resume();
	t.resume();
	t.resume();
	t.resume();
	t.resume();
	t.resume();
	t.resume();
	t.resume();
	t.resume();
	printf("return is %d\n", t.get());
}
