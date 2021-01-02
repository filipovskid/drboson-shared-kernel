package com.filipovski.drboson.sharedkernel.domain.base;

public abstract class AggregateRoot<ID extends DomainObjectId> extends AbstractEntity<ID> {

    public AggregateRoot() {}

    public AggregateRoot(ID id) {
        super(id);
    }
}
