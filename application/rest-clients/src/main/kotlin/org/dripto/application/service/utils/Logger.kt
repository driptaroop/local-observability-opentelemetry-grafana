package org.dripto.application.service.utils

import org.slf4j.Logger
import org.slf4j.LoggerFactory
import kotlin.reflect.KClass

val loggerMap = hashMapOf<KClass<*>, Logger>()
inline val <reified T> T.log: Logger
    get() = loggerMap.getOrPut(T::class) {
        LoggerFactory.getLogger(
            if (T::class.isCompanion) T::class.java.enclosingClass else T::class.java)
    }