# راهنمای استقرار CYRUS

## پیش‌نیازها
- یک سرویس میزبانی سازگار با Docker و پشتیبانی از پورت متغیر `PORT`
- پروژه Supabase آماده با جدول‌ها، سیاست‌های RLS، RPCها و Storage مربوط به CYRUS
- دامنه و HTTPS برای استفاده عمومی

## ساخت و اجرا

### روش ساده با Docker Compose

در ریشه مخزن، فایل نمونه را کپی و مقادیر واقعی را فقط در فایل محلی `.env` وارد کنید:

```sh
cp .env.example .env
# فایل .env را ویرایش و مقادیر واقعی را وارد کنید
docker compose up -d --build
docker compose ps
```

برای مشاهده گزارش‌ها: `docker compose logs -f cyrus` و برای توقف: `docker compose down`.
فایل `.env` محرمانه است و نباید در Git بارگذاری شود. Compose سلامت پردازه را از مسیر `/healthz` کنترل می‌کند.

### اجرای دستی Docker

در ریشه مخزن:

```sh
docker build -t cyrus-messenger .
docker run --rm -p 8080:8080 \
  -e PORT=8080 \
  -e SUPABASE_URL="https://YOUR-PROJECT.supabase.co" \
  -e SUPABASE_KEY="YOUR_SUPABASE_ANON_OR_PUBLISHABLE_KEY" \
  -e SECRET_KEY="GENERATE_A_LONG_RANDOM_SECRET" \
  -e COOKIE_SECURE=1 \
  cyrus-messenger
```

در سرویس میزبانی، همین متغیرها را در بخش Secrets / Environment Variables تنظیم کنید؛ فایل `.env` را در مخزن قرار ندهید.

## متغیرهای ضروری
- `SUPABASE_URL`: نشانی پروژه Supabase.
- `SUPABASE_KEY`: کلید عمومی anon یا publishable پروژه؛ هرگز service-role key را در برنامه وب قرار ندهید.
- `SECRET_KEY`: یک راز تصادفی طولانی و ثابت. آن را در هر بار استقرار تغییر ندهید، وگرنه نشست‌های کاربران باطل می‌شوند.
- `COOKIE_SECURE=1`: کوکی نشست فقط روی HTTPS ارسال شود. برای استقرار عمومی HTTPS الزامی است.

## بررسی سلامت سرویس
- `GET /healthz`: زنده بودن پردازه وب را گزارش می‌کند.
- `GET /readyz`: وجود تنظیمات Supabase و دسترسی به Auth API را بررسی می‌کند؛ در صورت آماده نبودن پاسخ HTTP 503 می‌دهد.

در تنظیمات پلتفرم، مسیر readiness را روی `/readyz` قرار دهید. مسیر liveness می‌تواند `/healthz` باشد.

## نکات عملیاتی
- این تصویر با کاربر غیر root اجرا می‌شود.
- یک worker و چهار thread برای شروع انتخاب شده تا مصرف حافظه کنترل شود.
- timeout برابر ۱۸۰ ثانیه است تا آپلودهای بزرگ فرصت تکمیل داشته باشند.
- برای اجرای چند نمونه، `SECRET_KEY` باید در همه نمونه‌ها یکسان باشد.
- فایل‌های رسانه در Supabase Storage ذخیره می‌شوند؛ فضای دیسک کانتینر برای نگهداری دائمی فایل‌ها استفاده نمی‌شود.
- پس از استقرار، ورود، ثبت‌نام، ارسال پیام و آپلود را با دو حساب مستقل و دو دستگاه جداگانه آزمایش کنید.

## وضعیت
وجود Dockerfile و health check به معنی استقرار زنده نیست. آدرس عمومی و آزمون واقعی دوکاربره باید پس از انتخاب میزبان ثبت و بررسی شوند.
