package org.androidtrustlab.observer;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.provider.DocumentsContract;
import android.provider.DocumentsContract.Document;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

/** Test-APK-only provider for exercising the production SAF publication path. */
public final class TestDocumentsProvider extends ContentProvider {
    public static final String AUTHORITY = "org.androidtrustlab.observer.test.documents";
    public static final String ROOT_DOCUMENT_ID = "root";

    private static final String METHOD_CREATE_DOCUMENT = "android:createDocument";
    private static final String METHOD_RENAME_DOCUMENT = "android:renameDocument";
    private static final String METHOD_DELETE_DOCUMENT = "android:deleteDocument";
    private static final String EXTRA_URI = "uri";
    private static final String[] DOCUMENT_COLUMNS = {
        Document.COLUMN_DOCUMENT_ID,
        Document.COLUMN_DISPLAY_NAME,
        Document.COLUMN_MIME_TYPE,
        Document.COLUMN_FLAGS,
        Document.COLUMN_SIZE,
    };

    private final Map<String, TestDocument> documents = new LinkedHashMap<>();
    private File storageDirectory;
    private int nextDocument;

    @Override
    public boolean onCreate() {
        storageDirectory = new File(requireContextCacheDir(), "saf-contract-documents");
        deleteRecursively(storageDirectory);
        if (!storageDirectory.mkdirs()) {
            throw new IllegalStateException("test document directory unavailable");
        }
        return true;
    }

    @Override
    public Cursor query(
            Uri uri,
            String[] projection,
            String selection,
            String[] selectionArgs,
            String sortOrder) {
        MatrixCursor cursor = new MatrixCursor(projection != null ? projection : DOCUMENT_COLUMNS);
        String documentId = DocumentsContract.getDocumentId(uri);
        if ("children".equals(uri.getLastPathSegment())) {
            if (!ROOT_DOCUMENT_ID.equals(documentId)) {
                throw new IllegalArgumentException("unexpected parent");
            }
            for (String childId : documents.keySet()) {
                includeDocument(cursor, childId);
            }
        } else {
            includeDocument(cursor, documentId);
        }
        return cursor;
    }

    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        return ParcelFileDescriptor.open(
                document(DocumentsContract.getDocumentId(uri)).file,
                ParcelFileDescriptor.parseMode(mode));
    }

    @SuppressWarnings("deprecation")
    @Override
    public Bundle call(String method, String arg, Bundle extras) {
        if (extras == null) {
            throw new IllegalArgumentException("missing extras");
        }
        Uri uri = extras.getParcelable(EXTRA_URI);
        if (uri == null) {
            throw new IllegalArgumentException("missing uri");
        }
        if (METHOD_CREATE_DOCUMENT.equals(method)) {
            if (!ROOT_DOCUMENT_ID.equals(DocumentsContract.getDocumentId(uri))) {
                throw new IllegalArgumentException("unexpected parent");
            }
            String documentId = "document-" + nextDocument++;
            File file = new File(storageDirectory, documentId);
            try {
                if (!file.createNewFile()) {
                    throw new IllegalStateException("test document already exists");
                }
            } catch (IOException exception) {
                throw new IllegalStateException("test document create failed", exception);
            }
            documents.put(
                    documentId,
                    new TestDocument(
                            requireString(extras, Document.COLUMN_DISPLAY_NAME),
                            requireString(extras, Document.COLUMN_MIME_TYPE),
                            file));
            Bundle result = new Bundle();
            result.putParcelable(
                    EXTRA_URI, DocumentsContract.buildDocumentUriUsingTree(uri, documentId));
            return result;
        }
        if (METHOD_RENAME_DOCUMENT.equals(method)) {
            document(DocumentsContract.getDocumentId(uri)).displayName =
                    requireString(extras, Document.COLUMN_DISPLAY_NAME);
            Bundle result = new Bundle();
            result.putParcelable(EXTRA_URI, uri);
            return result;
        }
        if (METHOD_DELETE_DOCUMENT.equals(method)) {
            TestDocument removed = documents.remove(DocumentsContract.getDocumentId(uri));
            if (removed == null || !removed.file.delete()) {
                throw new IllegalStateException("test document delete failed");
            }
            return new Bundle();
        }
        Bundle result = super.call(method, arg, extras);
        return result != null ? result : new Bundle();
    }

    @Override
    public String getType(Uri uri) {
        String documentId = DocumentsContract.getDocumentId(uri);
        return ROOT_DOCUMENT_ID.equals(documentId)
                ? Document.MIME_TYPE_DIR
                : document(documentId).mimeType;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int update(
            Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        throw new UnsupportedOperationException();
    }

    private void includeDocument(MatrixCursor cursor, String documentId) {
        if (ROOT_DOCUMENT_ID.equals(documentId)) {
            cursor.newRow()
                    .add(Document.COLUMN_DOCUMENT_ID, ROOT_DOCUMENT_ID)
                    .add(Document.COLUMN_DISPLAY_NAME, "root")
                    .add(Document.COLUMN_MIME_TYPE, Document.MIME_TYPE_DIR)
                    .add(Document.COLUMN_FLAGS, Document.FLAG_DIR_SUPPORTS_CREATE);
            return;
        }
        TestDocument document = document(documentId);
        cursor.newRow()
                .add(Document.COLUMN_DOCUMENT_ID, documentId)
                .add(Document.COLUMN_DISPLAY_NAME, document.displayName)
                .add(Document.COLUMN_MIME_TYPE, document.mimeType)
                .add(
                        Document.COLUMN_FLAGS,
                        Document.FLAG_SUPPORTS_WRITE
                                | Document.FLAG_SUPPORTS_DELETE
                                | Document.FLAG_SUPPORTS_RENAME)
                .add(Document.COLUMN_SIZE, document.file.length());
    }

    private TestDocument document(String documentId) {
        TestDocument document = documents.get(documentId);
        if (document == null) {
            throw new IllegalArgumentException("unknown test document");
        }
        return document;
    }

    private File requireContextCacheDir() {
        if (getContext() == null) {
            throw new IllegalStateException("provider has no context");
        }
        return getContext().getCacheDir();
    }

    private static String requireString(Bundle values, String key) {
        String value = values.getString(key);
        if (value == null) {
            throw new IllegalArgumentException("missing " + key);
        }
        return value;
    }

    private static void deleteRecursively(File file) {
        File[] children = file.listFiles();
        if (children != null) {
            for (File child : children) {
                deleteRecursively(child);
            }
        }
        if (file.exists() && !file.delete()) {
            throw new IllegalStateException("test document cleanup failed");
        }
    }

    private static final class TestDocument {
        private String displayName;
        private final String mimeType;
        private final File file;

        private TestDocument(String displayName, String mimeType, File file) {
            this.displayName = displayName;
            this.mimeType = mimeType;
            this.file = file;
        }
    }
}
