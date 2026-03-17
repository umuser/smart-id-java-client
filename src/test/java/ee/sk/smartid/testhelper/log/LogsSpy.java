package ee.sk.smartid.testhelper.log;

/*-
 * #%L
 * Smart ID sample Java client
 * %%
 * Copyright (C) 2018 - 2026 SK ID Solutions AS
 * %%
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 * #L%
 */

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.function.Predicate;

public final class LogsSpy {

    private Logger logger;
    private ListAppender<ILoggingEvent> appender;
    private Level initialLevel;

    void prepare() {
        appender = new ListAppender<>();
        logger = (Logger) LoggerFactory.getLogger("ee.sk.smartid");
        logger.addAppender(appender);
        initialLevel = logger.getLevel();
        logger.setLevel(Level.TRACE);
        appender.start();
    }

    void reset() {
        logger.setLevel(initialLevel);
        logger.detachAppender(appender);
    }

    public LogsSpy shouldHave(Level level, String content) {
        boolean found = logEvents().stream().anyMatch(withLog(level, content));
        assertTrue(found, "Expected at least one log entry with level " + level + " and content: " + content);

        return this;
    }

    public LogsSpy shouldHave(Level level, String content, int count) {
        long actualCount = logEvents().stream()
                .filter(withLog(level, content))
                .count();

        assertEquals(count, actualCount, "Expected " + count + " log entries with level " + level + " and content: " + content);

        return this;
    }

    public LogsSpy shouldNotHave(Level level, String content) {
        boolean found = logEvents().stream().anyMatch(withLog(level, content));
        assertFalse(found, "Expected no log entries with level " + level + " and content: " + content);

        return this;
    }

    private List<ILoggingEvent> logEvents() {
        // Copy the list to avoid concurrent modification exceptions
        return List.copyOf(appender.list);
    }

    private Predicate<ILoggingEvent> withLog(Level level, String content) {
        return event -> level.equals(event.getLevel()) && event.toString().contains(content);
    }
}
