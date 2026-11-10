package eu.portcullis.signin;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Stream;

/**
 * A lenient stand-in for a Keycloak interface: answers by method name,
 * records every call, runs an interface's default methods, and otherwise
 * returns an empty value (false, 0, an empty stream / collection / Optional,
 * else null).
 */
final class Fake implements InvocationHandler {
    record Call(String method, Object[] args) {}

    private final String name;
    private final Map<String, Function<Object[], Object>> answers = new HashMap<>();
    private Class<?> self;
    final List<Call> calls = new ArrayList<>();

    private Fake(String name) {
        this.name = name;
    }

    static Fake named(String name) {
        return new Fake(name);
    }

    Fake on(String method, Function<Object[], Object> answer) {
        answers.put(method, answer);
        return this;
    }

    Fake ret(String method, Object value) {
        return on(method, a -> value);
    }

    /** Methods returning this type (a fluent builder) return the proxy itself. */
    Fake fluent(Class<?> type) {
        self = type;
        return this;
    }

    <T> T as(Class<T> type) {
        return type.cast(Proxy.newProxyInstance(Fake.class.getClassLoader(), new Class<?>[] {type}, this));
    }

    List<Object[]> calls(String method) {
        return calls.stream().filter(c -> c.method().equals(method)).map(Call::args).toList();
    }

    boolean called(String method) {
        return !calls(method).isEmpty();
    }

    @Override
    public Object invoke(Object proxy, Method m, Object[] args) throws Throwable {
        Object[] a = args == null ? new Object[0] : args;
        calls.add(new Call(m.getName(), a));
        Function<Object[], Object> answer = answers.get(m.getName());
        if (answer != null) {
            return answer.apply(a);
        }
        switch (m.getName()) {
            case "equals":
                return proxy == a[0];
            case "hashCode":
                return System.identityHashCode(proxy);
            case "toString":
                return name;
            default:
                break;
        }
        if (self != null && m.getReturnType() == self) {
            return proxy;
        }
        if (m.isDefault()) {
            return InvocationHandler.invokeDefault(proxy, m, args);
        }
        return empty(m.getReturnType());
    }

    private static Object empty(Class<?> t) {
        if (t == boolean.class) {
            return false;
        }
        if (t == int.class || t == short.class || t == byte.class) {
            return 0;
        }
        if (t == long.class) {
            return 0L;
        }
        if (t == double.class || t == float.class) {
            return 0.0;
        }
        if (t == char.class) {
            return '\0';
        }
        if (t == Stream.class) {
            return Stream.empty();
        }
        if (t == Optional.class) {
            return Optional.empty();
        }
        if (t == Map.class) {
            return new HashMap<>();
        }
        if (t == Set.class) {
            return new java.util.HashSet<>();
        }
        if (t == List.class || t == Collection.class) {
            return new ArrayList<>();
        }
        return null;
    }
}
