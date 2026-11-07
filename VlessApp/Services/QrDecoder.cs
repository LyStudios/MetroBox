using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Windows.Graphics.Imaging;
using Windows.Storage.Streams;

namespace VlessApp.Services
{
    /// <summary>Офлайн-распознавание QR-кода на снимке (ZXing.Net). Без привязки к UI.</summary>
    public static class QrDecoder
    {
        // Многопроходное декодирование потока изображения в разных разрешениях
        // Снимок с камеры телефона — это шестнадцать мегапикселей, и ZXing прогоняет
        // по ним два бинаризатора. Раньше счёт шёл прямо в потоке интерфейса, да ещё
        // начиная с полного разрешения: приложение замирало намертво, и со стороны это
        // выглядело как зависание. Теперь счёт уходит в фоновый поток, а проходы идут
        // от мелких размеров к крупным — код обычно читается уже на первом из них.
        public static async Task<string> DecodeAsync(IRandomAccessStream stream, Action<string> progress = null)
        {
            try
            {
                var decoder = await BitmapDecoder.CreateAsync(stream);
                uint origWidth = decoder.PixelWidth;
                uint origHeight = decoder.PixelHeight;
                AppLog.W($"[QR] Снимок {origWidth}×{origHeight}, начинаю разбор.");

                foreach (uint targetSize in new uint[] { 600, 900, 1400, 0 })
                {
                    var transform = new BitmapTransform();

                    // 0 — последний проход, по оригиналу: он самый дорогой, и нужен только
                    // там, где мелкий код на крупном кадре после сжатия рассыпается.
                    if (targetSize != 0)
                    {
                        if (origWidth <= targetSize && origHeight <= targetSize) continue;

                        float ratio = (float)origWidth / origHeight;
                        if (origWidth > origHeight)
                        {
                            transform.ScaledWidth = targetSize;
                            transform.ScaledHeight = (uint)(targetSize / ratio);
                        }
                        else
                        {
                            transform.ScaledHeight = targetSize;
                            transform.ScaledWidth = (uint)(targetSize * ratio);
                        }
                        transform.InterpolationMode = BitmapInterpolationMode.Linear;
                    }

                    progress?.Invoke(targetSize != 0
                        ? $"Распознавание ({targetSize} точек)..."
                        : "Распознавание (полный размер)...");

                    using (var bmp = await decoder.GetSoftwareBitmapAsync(
                        BitmapPixelFormat.Bgra8,
                        BitmapAlphaMode.Premultiplied,
                        transform,
                        ExifOrientationMode.RespectExifOrientation,
                        ColorManagementMode.ColorManageToSRgb))
                    {
                        // Именно этот счёт и держал интерфейс. Ожидание здесь возвращает
                        // управление окну: полоса состояния обновляется, кнопки живые.
                        string res = await Task.Run(() => DecodeWithBinarizers(bmp));
                        if (!string.IsNullOrEmpty(res))
                        {
                            AppLog.W($"[QR] Код прочитан на проходе {(targetSize != 0 ? targetSize.ToString() : "оригинал")}, длина {res.Length}.");
                            return res;
                        }
                    }
                }

                AppLog.W("[QR] Код не прочитан ни на одном проходе.");
            }
            catch (Exception ex)
            {
                AppLog.W("[QR] Ошибка разбора снимка: " + ex.Message);
            }
            return null;
        }

        // Попытка декодирования конкретного кадра двумя разными математическими бинаризаторами
        private static string DecodeWithBinarizers(SoftwareBitmap bmp)
        {
            try
            {
                // Метод 1: HybridBinarizer (по умолчанию). Отлично справляется с тенями и градиентами освещения.
                var readerHybrid = new ZXing.BarcodeReader();
                readerHybrid.Options = new ZXing.Common.DecodingOptions
                {
                    TryHarder = true,
                    TryInverted = true,
                    PossibleFormats = new List<ZXing.BarcodeFormat> { ZXing.BarcodeFormat.QR_CODE }
                };
                var src = new ZXing.SoftwareBitmapLuminanceSource(bmp);
                var result = readerHybrid.Decode(src);
                if (result != null && !string.IsNullOrEmpty(result.Text)) return result.Text;

                // Метод 2: GlobalHistogramBinarizer. Отлично восстанавливает смазанные/расфокусированные границы.
                var readerGlobal = new ZXing.BarcodeReader(
                    null,
                    (b) => new ZXing.SoftwareBitmapLuminanceSource(b),
                    (luminanceSource) => new ZXing.Common.GlobalHistogramBinarizer(luminanceSource)
                );
                readerGlobal.Options = new ZXing.Common.DecodingOptions
                {
                    TryHarder = true,
                    TryInverted = true,
                    PossibleFormats = new List<ZXing.BarcodeFormat> { ZXing.BarcodeFormat.QR_CODE }
                };
                result = readerGlobal.Decode(bmp);
                if (result != null && !string.IsNullOrEmpty(result.Text)) return result.Text;
            }
            catch { }
            return null;
        }
    }
}

