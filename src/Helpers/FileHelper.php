<?php

namespace InsuranceCore\Helpers\Helpers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Http;

class FileHelper
{
    public static function uploadFileToPathOld(Request $request, $inputName, $destinationPath, $newFileName = null)
    {
        if ($request->hasFile($inputName)) {
            $file = $request->file($inputName);
            $originalFileName = $file->getClientOriginalName();
            $mimeType = $file->getClientMimeType();
            $extension = $file->getClientOriginalExtension();
            $fileName = $newFileName ?: uniqid() . "." . $extension;
            $storedPath = $file->move($destinationPath, $fileName);

            return [
                "file_name" => basename($storedPath),
                "original_file_name" => $originalFileName,
                "mime_type" => $mimeType,
                "file_extension" => $extension,
            ];
        }
        return [];
    }

    public static function uploadFileToPath(Request $request, $inputName, $destinationPath, $newFileName = null)
    {
        if ($request->file($inputName)) {
            $file = $request->file($inputName);
            $originalFileName = $file->getClientOriginalName();
            $mimeType = $file->getClientMimeType();
            $extension = $file->getClientOriginalExtension();
            $fileName = $newFileName ?: (string) time() . rand(100000, 999999) . "." . $extension;

            if (env("FILESYSTEM_DISK") == "s3") {
                $path = Storage::disk("s3")->putFileAs($destinationPath, $file, $fileName);
            } else {
                public_path("uploaded_document/" . $destinationPath . $originalFileName);
            }

            return [
                "file_name" => $fileName,
                "original_file_name" => $originalFileName,
                "mime_type" => $mimeType,
                "file_extension" => $extension,
            ];
        } else {
            $file = $inputName;
            $originalFileName = $file->getClientOriginalName();
            $mimeType = $file->getClientMimeType();
            $extension = $file->getClientOriginalExtension();
            $fileName = $newFileName ?: (string) time() . rand(100000, 999999) . "." . $extension;

            if (env("FILESYSTEM_DISK") == "s3") {
                $path = Storage::disk("s3")->putFileAs($destinationPath, $file, $fileName);
            } else {
                public_path("uploaded_document/" . $destinationPath . $originalFileName);
            }

            return [
                "file_name" => $fileName,
                "original_file_name" => $originalFileName,
                "mime_type" => $mimeType,
                "file_extension" => $extension,
            ];
        }
    }

    public static function downloadPolicyDocument($policyNumber, $url, $base64 = false)
    {
        $stream = fopen("php://temp", "w+");
        if (!$stream) {
            throw new \Exception("Unable to open temporary stream.");
        }

        try {
            if ($base64) {
                $pdfData = base64_decode($base64);
                $fileName = $policyNumber . ".pdf";
                fwrite($stream, $pdfData);
            } else {
                $response = Http::withOptions(["stream" => true])->get($url);
                if (!$response->successful()) {
                    throw new \Exception("Failed to fetch the file. HTTP status: " . $response->status());
                }
                $responseBody = $response->toPsrResponse()->getBody();
                while (!$responseBody->eof()) {
                    fwrite($stream, $responseBody->read(1024));
                }
            }
            rewind($stream);
            $fileName = $policyNumber . ".pdf";
            $destinationPath = "onlinePolicy/" . $policyNumber . "/" . $fileName;
            $disk = Storage::disk("s3");
            if ($disk->exists($destinationPath)) {
                $message = "The file already exists on S3.";
            } else {
                $disk->put($destinationPath, $stream);
                $message = "File uploaded to S3 successfully.";
            }
            \Log::info($message);
            $link = $disk->temporaryUrl($destinationPath, now()->addHours(12));
            return [
                "message" => $message,
                "link" => $link,
            ];
        } catch (\Exception $e) {
            fclose($stream);
            return [
                "message" => "Policy generation failed!" . $e->getMessage(),
                "link" => "",
            ];
        } finally {
            fclose($stream);
        }
    }

    public static function uploadMultiFileToPath(Request $request, $inputName, $destinationPath, $newFileName = null)
    {
        $uploadedFiles = [];

        if ($request->file($inputName)) {
            $files = $request->file($inputName);
            foreach ($files as $file) {
                $originalFileName = $file->getClientOriginalName();
                $mimeType = $file->getClientMimeType();
                $extension = $file->getClientOriginalExtension();
                $fileName = $newFileName ?: (string) time() . rand(100000, 999999) . "." . $extension;

                if (env("FILESYSTEM_DISK") == "s3") {
                    $path = Storage::disk("s3")->putFileAs($destinationPath, $file, $fileName);
                } else {
                    $file->move(public_path($destinationPath), $fileName);
                }

                $uploadedFiles[] = [
                    "file_name" => $fileName,
                    "original_file_name" => $originalFileName,
                    "mime_type" => $mimeType,
                    "file_extension" => $extension,
                    "file_path" => $destinationPath . '/' . $fileName,
                ];
            }
        }

        return $uploadedFiles;
    }
} 

