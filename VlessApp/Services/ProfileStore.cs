using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Windows.Storage;

namespace VlessApp.Services
{
    /// <summary>Хранилище списка профилей (profiles.json в LocalFolder).</summary>
    public sealed class ProfileStore
    {
        // Список живёт в одном файле. Пишется он через FileIO: поток, который выдаёт
        // OpenStreamForWriteAsync, дописывает файл уже после Dispose, и если телефон
        // усыплял приложение сразу после импорта, запись не доходила — подписка была в
        // списке до перезапуска и пропадала после него.
        private const string ProfilesFile = "profiles.json";

        private readonly SemaphoreSlim _saveLock = new SemaphoreSlim(1, 1);

        private static string Serialize(List<VlessProfile> profiles)
        {
            using (var ms = new MemoryStream())
            {
                new DataContractJsonSerializer(typeof(List<VlessProfile>)).WriteObject(ms, profiles);
                return Encoding.UTF8.GetString(ms.ToArray(), 0, (int)ms.Length);
            }
        }

        public async Task SaveAsync(List<VlessProfile> profiles)
        {
            await _saveLock.WaitAsync();
            try
            {
                string json = Serialize(profiles);
                var folder = ApplicationData.Current.LocalFolder;

                var file = await folder.CreateFileAsync(ProfilesFile, CreationCollisionOption.ReplaceExisting);

                // Байтами, а не текстом: WriteTextAsync ставит в начало метку порядка
                // байтов, а разборщик JSON о неё спотыкается — файл, записанный этой
                // версией, не прочитала бы ни одна прежняя.
                await FileIO.WriteBytesAsync(file, Encoding.UTF8.GetBytes(json));

                // Записанное перечитывается: «сохранил» без проверки уже один раз означало
                // пустой список после перезапуска, и в журнале это выглядело как успех.
                ulong written = (await file.GetBasicPropertiesAsync()).Size;
                AppLog.W($"[ПРОФИЛИ] Сохранено: {profiles.Count} шт., на диске {written} байт.");
            }
            catch (Exception ex)
            {
                AppLog.W("[ПРОФИЛИ] СОХРАНИТЬ НЕ УДАЛОСЬ: " + ex);
            }
            finally
            {
                _saveLock.Release();
            }
        }

        // Возвращает null, если файла нет или он не читается.
        private static async Task<List<VlessProfile>> TryReadAsync(string name)
        {
            try
            {
                var file = await ApplicationData.Current.LocalFolder.GetFileAsync(name);

                // Через FileIO, а не через поток: файл могли положить с меткой порядка
                // байтов, и разборщик JSON споткнулся бы о неё на первом же символе.
                string text = await FileIO.ReadTextAsync(file);
                text = text.TrimStart('﻿');
                using (var ms = new MemoryStream(Encoding.UTF8.GetBytes(text)))
                {
                    var serializer = new DataContractJsonSerializer(typeof(List<VlessProfile>));
                    return (List<VlessProfile>)serializer.ReadObject(ms) ?? new List<VlessProfile>();
                }
            }
            catch (Exception ex)
            {
                AppLog.W($"[ПРОФИЛИ] {name} не прочитан: {ex.Message}");
                return null;
            }
        }

        /// <summary>Читает сохранённые профили; null, если файла нет или он не читается.</summary>
        public Task<List<VlessProfile>> LoadAsync() => TryReadAsync(ProfilesFile);
    }
}

