Вы правы, создание обертки над контейнером требует понимания жизненного цикла Spring AMQP, но это самый элегантный способ. Основная сложность в том, что Spring ожидает, что один `@RabbitListener` — это один `MessageListenerContainer`.

Нам не нужно писать «настоящий» контейнер с нуля. Мы создадим **менеджер**, который будет делегировать команды (start, stop, setup) списку реальных контейнеров.

### 1. Реализация CompositeMessageListenerContainer

Этот класс будет просто «группировщиком». Spring вызовет у него `setupMessageListener`, `start()` и другие методы, а мы пробросим их всем вложенным контейнерам.

```java
import org.springframework.amqp.rabbit.listener.MessageListenerContainer;
import org.springframework.amqp.core.MessageListener;

import java.util.ArrayList;
import java.util.List;

public class CompositeMessageListenerContainer implements MessageListenerContainer {

    private final List<MessageListenerContainer> containers = new ArrayList<>();

    public void addContainer(MessageListenerContainer container) {
        this.containers.add(container);
    }

    @Override
    public void setupMessageListener(Object messageListener) {
        // Когда Spring передает логику обработки (метод с @RabbitListener), 
        // мы отдаем её каждому контейнеру во всех кластерах
        containers.forEach(c -> c.setupMessageListener(messageListener));
    }

    @Override
    public void start() {
        containers.forEach(MessageListenerContainer::start);
    }

    @Override
    public void stop() {
        containers.forEach(MessageListenerContainer::stop);
    }

    @Override
    public boolean isRunning() {
        // Считаем, что мы работаем, если жив хотя бы один кластер
        return containers.stream().anyMatch(MessageListenerContainer::isRunning);
    }

    // Остальные методы интерфейса (shutdown, pause и т.д.) реализуются по тому же принципу делегирования
    // Многие можно оставить пустыми или пробросить через .forEach()
}
```

### 2. Создание Composite-фабрики

Эта фабрика заменяет стандартную. Она берет список ваших настроек кластеров и для каждой аннотации `@RabbitListener` создает "пачку" контейнеров.

```java
public class MultiClusterContainerFactory implements RabbitListenerContainerFactory<CompositeMessageListenerContainer> {

    private final List<SimpleRabbitListenerContainerFactory> internalFactories;

    public MultiClusterContainerFactory(List<SimpleRabbitListenerContainerFactory> factories) {
        this.internalFactories = factories;
    }

    @Override
    public CompositeMessageListenerContainer createListenerContainer(RabbitListenerEndpoint endpoint) {
        CompositeMessageListenerContainer composite = new CompositeMessageListenerContainer();
        
        for (SimpleRabbitListenerContainerFactory factory : internalFactories) {
            // Создаем реальный контейнер для конкретного кластера
            MessageListenerContainer container = factory.createListenerContainer(endpoint);
            composite.addContainer(container);
        }
        
        return composite;
    }
}
```

### 3. Регистрация в стартере (BeanPostProcessor не нужен)

Вам достаточно создать один бин с именем `rabbitListenerContainerFactory`. Spring Boot увидит его и не будет создавать дефолтную фабрику.

```java
@Configuration
public class MultiRabbitAutoConfiguration {

    @Bean(name = "rabbitListenerContainerFactory")
    public MultiClusterContainerFactory multiClusterContainerFactory(MultiRabbitProperties props) {
        List<SimpleRabbitListenerContainerFactory> factories = new ArrayList<>();
        
        for (ClusterConfig config : props.getClusters()) {
            // Создаем ConnectionFactory для каждого кластера
            CachingConnectionFactory cf = new CachingConnectionFactory();
            cf.setAddresses(config.getAddresses()); // Например: "host1:5672,host2:5672"
            cf.setUsername(config.getUsername());
            cf.setPassword(config.getPassword());
            
            // Настраиваем фабрику (важно скопировать настройки пропертей, если нужно)
            SimpleRabbitListenerContainerFactory factory = new SimpleRabbitListenerContainerFactory();
            factory.setConnectionFactory(cf);
            factory.setConcurrentConsumers(config.getConcurrency());
            
            factories.add(factory);
        }
        
        return new MultiClusterContainerFactory(factories);
    }
}
```

### Почему это решает вашу задачу:
* **Для существующего кода:** Аннотация `@RabbitListener` просто говорит: "Я хочу слушать очередь X". 
* **Для Spring:** Он идет в `rabbitListenerContainerFactory`, просит создать контейнер.
* **Ваша логика:** Фабрика возвращает `CompositeMessageListenerContainer`, который внутри себя поднимает 2, 3 или 10 соединений с разными кластерами.
* **Результат:** Сообщения из всех кластеров будут стекаться в один и тот же метод вашего бина. Если один кластер упадет, `SimpleMessageListenerContainer` внутри композита начнет бесконечные попытки переподключения (стандартное поведение RabbitMQ), а остальные продолжат работать.

---
**Важный совет по стабильности:**
Если вы слушаете несколько кластеров, у которых **идентичные** очереди, убедитесь, что вы используете **Manual Ack** или настроили идемпотентность. В случае "мигания" сети сообщение может прийти из обоих кластеров почти одновременно (если ваша система публикации шлет их в оба места для надежности).
